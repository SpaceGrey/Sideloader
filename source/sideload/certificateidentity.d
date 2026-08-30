module sideload.certificateidentity;

import std.algorithm.searching;
import std.digest.sha;
import file = std.file;
import std.path;
import std.uni;

import slf4d;

import botan.constants;
version = X509;
import botan.cert.x509.certstor;
import botan.cert.x509.x509_crl;
import botan.cert.x509.x509self;
import botan.pubkey.algo.rsa;
import botan.rng.rng;

import constants;
import server.appleaccount;
import server.developersession;

import sideload.bundle;

class CertificateIdentity {
    RandomNumberGenerator rng = void;
    X509Certificate certificate = void;
    RSAPrivateKey privateKey = void;

    string keyFile;

    this(X509Certificate certificate, RSAPrivateKey privateKey) {
        rng = RandomNumberGenerator.makeRng();
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    this(
        string configurationPath,
        DeveloperSession appleAccount,
        DeveloperTeam team,
        bool reuseExisting = true,
        bool requireExisting = false,
    ) {
        auto log = getLogger();
        scope(success) log.debug_("Certificate retrieved successfully.");

        string accountKeyPath = configurationPath.buildPath("keys").buildPath(sha1Of(appleAccount.appleId).toHexString().toLower());
        if (!file.exists(accountKeyPath)) {
            file.mkdirRecurse(accountKeyPath);
        }

        auto identitiesPath = accountKeyPath.buildPath("identities");
        auto identityPath = identitiesPath.buildPath(team.teamId);
        if (!file.exists(identityPath)) {
            file.mkdirRecurse(identityPath);
        }

        keyFile = identityPath.buildPath("key.pem");
        auto certFile = identityPath.buildPath("cert.pem");
        auto legacyKeyFile = accountKeyPath.buildPath("key.pem");
        auto legacyCertFile = accountKeyPath.buildPath("cert.pem");

        rng = RandomNumberGenerator.makeRng();

        void persistKey() {
            file.write(keyFile, botan.pubkey.pkcs8.PEM_encode(privateKey));
            version (Posix) {
                import std.conv : octal;
                file.setAttributes(keyFile, octal!600);
            }
        }

        void persistCertificate() {
            try {
                if (!file.exists(keyFile)) {
                    persistKey();
                }
                file.write(certFile, certificate.PEM_encode());
                version (Posix) {
                    import std.conv : octal;
                    file.setAttributes(certFile, octal!600);
                }
                log.infoF!"Saved development certificate to %s"(certFile);
            } catch (Exception e) {
                log.warnF!"Could not save certificate: %s"(e.msg);
            }
        }

        bool hasKey = false;
        if (reuseExisting && file.exists(keyFile)) {
            log.debug_("Using the saved key for this team.");
            privateKey = RSAPrivateKey(loadKey(keyFile, rng));
            hasKey = true;
            Vector!ubyte ourPublicKey = privateKey.x509SubjectPublicKey();

            if (file.exists(certFile)) {
                try {
                    auto saved = X509Certificate(certFile, false);
                    if (saved.subjectPublicKey().x509SubjectPublicKey() == ourPublicKey) {
                        if (requireExisting) {
                            log.info("Using the selected saved development certificate.");
                            certificate = saved;
                            return;
                        }
                        log.info("Found saved development certificate; verifying it with Apple.");
                        certificate = saved;
                    }
                    log.warn("Saved certificate does not match the private key; fetching a matching one.");
                } catch (Exception e) {
                    log.warnF!"Could not load saved certificate (%s); fetching a matching one."(e.msg);
                }
            }
        } else if (reuseExisting && file.exists(legacyKeyFile)) {
            log.debug_("Trying the legacy saved key for this team.");
            privateKey = RSAPrivateKey(loadKey(legacyKeyFile, rng));
            hasKey = true;
            if (file.exists(legacyCertFile)) {
                try {
                    auto saved = X509Certificate(legacyCertFile, false);
                    if (saved.subjectPublicKey().x509SubjectPublicKey() == privateKey.x509SubjectPublicKey()) {
                        if (requireExisting) {
                            log.info("Using the selected legacy development certificate.");
                            certificate = saved;
                            return;
                        }
                        certificate = saved;
                    }
                } catch (Exception e) {
                    log.warnF!"Could not load the legacy certificate (%s); fetching a matching one."(e.msg);
                }
            }
        }

        if (reuseExisting && hasKey) {
            log.debug_("Checking if any certificate online is matching the private key...");
            Vector!ubyte ourPublicKey = privateKey.x509SubjectPublicKey();
            auto certificates = appleAccount.listAllDevelopmentCerts!iOS(team).unwrap();
            foreach (cert; certificates) {
                Vector!ubyte certContent = Vector!ubyte(cert.certContent);
                auto x509cert = X509Certificate(certContent, false);
                if (x509cert.subjectPublicKey().x509SubjectPublicKey() == ourPublicKey) {
                    log.info("Reusing the development certificate already registered with this Apple ID.");
                    certificate = X509Certificate(Vector!ubyte(cert.certContent), false);
                    persistCertificate();
                    return;
                }
            }
        }

        if (requireExisting) {
            if (hasKey) {
                throw new Exception("The selected saved certificate is no longer registered for this Apple Developer team. Choose a new certificate and try again.");
            }
            throw new Exception("The selected saved certificate no longer has its private key. Choose a new certificate and try again.");
        }

        if (!hasKey || !reuseExisting) {
            log.debug_("Generating a new RSA key for this team.");
            privateKey = RSAPrivateKey(rng, 2048);
            persistKey();
        }

        X509CertOptions subject;
        subject.country = "US";
        subject.state = "STATE";
        subject.locality = "LOCAL";
        subject.organization = "ORGANIZATION";
        subject.common_name = "CN";

        auto certRequest = createCertReq(subject, privateKey.m_priv, "SHA-256", rng);

        log.debug_("Submitting a new certificate request to Apple...");

        auto certificateId = appleAccount.submitDevelopmentCSR!iOS(team, certRequest.PEM_encode()).unwrap();
        auto appleCertificateInfo = appleAccount.listAllDevelopmentCerts!iOS(team).unwrap().find!((cert) => cert.certificateId == certificateId)[0];
        certificate = X509Certificate(Vector!ubyte(appleCertificateInfo.certContent), false);
        persistCertificate();
    }
}
