module certificate;

import std.algorithm;
import std.algorithm.searching : countUntil;
import std.array;
import std.digest.sha;
import std.exception;
import file = std.file;
import std.path;
import std.process : execute;
import std.stdio;
import std.string : strip;
import std.sumtype;
import std.typecons;
import std.uni;

import slf4d;
import slf4d.default_provider;

import botan.cert.x509.pkcs10;
import botan.filters.data_src;

import argparse;

import plist;
import server.developersession;

import cli_frontend;

@(Command("cert").Description("Manage certificates."))
struct CertificateCommand
{
    int opCall()
    {
        return cmd.match!(
                (ListCerts cmd) => cmd(),
                (HistoryCerts cmd) => cmd(),
                (SubmitCert cmd) => cmd(),
                (RevokeCert cmd) => cmd()
        );
    }

    @SubCommands
    SumType!(ListCerts, HistoryCerts, SubmitCert, RevokeCert) cmd;
}

@(Command("history").Description("List locally saved signing certificates without logging in."))
struct HistoryCerts
{
    @(NamedArgument("gsv").Description("Print a machine-readable certificate list for GSV."))
    bool gsv = false;

    private string teamIdFromCertificate(string certificatePath)
    {
        try {
            auto result = execute(["/usr/bin/openssl", "x509", "-in", certificatePath, "-noout", "-subject"]);
            if (result.status != 0) {
                return null;
            }
            string marker = "OU = ";
            auto start = result.output.countUntil(marker);
            if (start < 0) {
                marker = "/OU=";
                start = result.output.countUntil(marker);
            }
            if (start < 0) {
                return null;
            }
            auto organizationalUnit = result.output[start + marker.length .. $];
            auto end = organizationalUnit.countUntil(",");
            auto slashEnd = organizationalUnit.countUntil("/");
            if (end < 0 || (slashEnd >= 0 && slashEnd < end)) {
                end = slashEnd;
            }
            if (end >= 0) {
                organizationalUnit = organizationalUnit[0 .. end];
            }
            auto teamId = organizationalUnit.strip();
            if (teamId.length > 0) {
                return teamId.idup;
            }
        } catch (Exception) {
            // A malformed historical certificate should not prevent the user
            // from choosing the explicit new-certificate path.
        }
        return null;
    }

    int opCall()
    {
        string configurationPath = systemConfigurationPath();
        auto accountPath = configurationPath.buildPath("account.plist");
        if (!file.exists(accountPath)) {
            if (gsv) writeln("GSV_CERT_HISTORY\tNONE");
            return 0;
        }

        string appleId;
        try {
            appleId = Plist.fromXml(cast(string) file.read(accountPath)).dict()["appleId"].str().native();
        } catch (Exception) {
            if (gsv) writeln("GSV_CERT_HISTORY\tNONE");
            return 0;
        }

        auto accountHash = (cast(string) sha1Of(appleId).toHexString()).toLower();
        auto keyPath = configurationPath.buildPath("keys").buildPath(accountHash);
        auto identitiesPath = keyPath.buildPath("identities");
        bool found = false;
        bool[string] seenTeamIds;

        void reportTeamCertificate(string teamId) {
            if (teamId in seenTeamIds) {
                return;
            }
            seenTeamIds[teamId] = true;
            found = true;
            if (gsv) {
                writefln!"GSV_CERT_HISTORY\t%s"(teamId);
            } else {
                writefln!"Saved certificate for team `%s`."(teamId);
            }
        }

        if (file.exists(identitiesPath)) {
            foreach (entry; file.dirEntries(identitiesPath, file.SpanMode.shallow)) {
                auto certificatePath = entry.name.buildPath("cert.pem");
                if (entry.isDir && file.exists(certificatePath) && file.exists(entry.name.buildPath("key.pem"))) {
                    reportTeamCertificate(baseName(entry.name));
                }
            }
        }

        // An earlier GSV build kept team certificates in this directory while
        // sharing the legacy account-level private key. Keep those users visible
        // to the new selector; signing will migrate the identity on first use.
        auto transitionalCertificatesPath = keyPath.buildPath("certificates");
        if (file.exists(transitionalCertificatesPath)) {
            foreach (entry; file.dirEntries(transitionalCertificatesPath, file.SpanMode.shallow)) {
                if (entry.isFile && extension(entry.name) == ".pem" && file.exists(keyPath.buildPath("key.pem"))) {
                    reportTeamCertificate(stripExtension(baseName(entry.name)));
                }
            }
        }

        auto legacyCertificatePath = keyPath.buildPath("cert.pem");
        if (file.exists(keyPath.buildPath("key.pem")) && file.exists(legacyCertificatePath)) {
            found = true;
            auto legacyTeamId = teamIdFromCertificate(legacyCertificatePath);
            if (legacyTeamId != null) {
                reportTeamCertificate(legacyTeamId);
            } else if (gsv) {
                writeln("GSV_CERT_HISTORY\tLEGACY");
            } else {
                writeln("Saved legacy certificate (team needs confirmation after login).");
            }
        }

        if (!found && gsv) {
            writeln("GSV_CERT_HISTORY\tNONE");
        }
        return 0;
    }
}

@(Command("list").Description("List certificates."))
struct ListCerts
{
    mixin LoginCommand;

    @(NamedArgument("team").Description("Team ID"))
    string teamId = null;

    int opCall()
    {
        auto log = getLogger();

        string configurationPath = systemConfigurationPath();

        scope provisioningData = initializeADI(configurationPath);
        scope adi = provisioningData.adi;
        scope akDevice = provisioningData.device;

        auto appleAccount = login(akDevice, adi);

        if (!appleAccount) {
            return 1;
        }

        auto teams = appleAccount.listTeams().unwrap();

        string teamId = this.teamId;
        if (teamId != null) {
            teams = teams.filter!((elem) => elem.teamId == teamId).array();
        }
        enforce(teams.length > 0, "No matching team found.");

        auto team = teams[0];

        auto certificates = appleAccount.listAllDevelopmentCerts!iOS(team).unwrap();

        writefln!"You have %d certificates registered."(certificates.length);
        writeln("Currently registered certificates:");
        foreach (certificate; certificates) {
            writefln!" - `%s` with the serial number `%s`, from the machine named `%s`."(certificate.name, certificate.serialNumber, certificate.machineName);
        }

        return 0;
    }
}

// @(Command("register").Description("Register a certificate for Sideloader if we don't already have one."))

@(Command("submit").Description("Submit a certificate signing request to Apple servers."))
struct SubmitCert
{
    mixin LoginCommand;

    @(NamedArgument("team").Description("Team ID"))
    string teamId = null;

    @(PositionalArgument(0).Description("CSR file"))
    string certificatePath;

    int opCall()
    {
        ubyte[] certificateData = readFile(certificatePath);
        auto cert = PKCS10Request(DataSourceMemory(certificateData.ptr, certificateData.length));

        auto log = getLogger();

        string configurationPath = systemConfigurationPath();

        scope provisioningData = initializeADI(configurationPath);
        scope adi = provisioningData.adi;
        scope akDevice = provisioningData.device;

        auto appleAccount = login(akDevice, adi);

        if (!appleAccount) {
            return 1;
        }

        auto teams = appleAccount.listTeams().unwrap();

        string teamId = this.teamId;
        if (teamId != null) {
            teams = teams.filter!((elem) => elem.teamId == teamId).array();
        }
        enforce(teams.length > 0, "No matching team found.");

        auto team = teams[0];

        appleAccount.submitDevelopmentCSR!iOS(team, cast(string) cert.PEM_encode()).unwrap();

        return 0;
    }
}

@(Command("revoke").Description("Revoke a certificate."))
struct RevokeCert
{
    mixin LoginCommand;

    @(NamedArgument("team").Description("Team ID"))
    string teamId = null;

    @(PositionalArgument(0).Description("certificate serial number"))
    string serialNumber;

    int opCall()
    {
        auto log = getLogger();

        string configurationPath = systemConfigurationPath();

        scope provisioningData = initializeADI(configurationPath);
        scope adi = provisioningData.adi;
        scope akDevice = provisioningData.device;

        auto appleAccount = login(akDevice, adi);

        if (!appleAccount) {
            return 1;
        }

        auto teams = appleAccount.listTeams().unwrap();

        string teamId = this.teamId;
        if (teamId != null) {
            teams = teams.filter!((elem) => elem.teamId == teamId).array();
        }
        enforce(teams.length > 0, "No matching team found.");

        auto team = teams[0];

        auto certificates = appleAccount.listAllDevelopmentCerts!iOS(team).unwrap();
        auto matchingCerts = certificates.filter!((cert) => cert.serialNumber == serialNumber).array();

        if (matchingCerts.length == 0) {
            log.error("No matching certificate found.");
            return 1;
        }

        enforce(matchingCerts.length == 1, "Multiple certificate matched?? To prevent any issue, ignoring the request.");

        appleAccount.revokeDevelopmentCert!iOS(team, matchingCerts[0]).unwrap();

        return 0;
    }
}
