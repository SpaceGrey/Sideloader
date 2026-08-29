module cli_frontend;

import core.stdc.stdlib;

import std.array;
import std.datetime;
import std.exception;
import std.format;
import std.parallelism;
import std.path;
import std.process;
import std.stdio;
import std.sumtype;
import std.string;
import std.traits;
import std.typecons;
import file = std.file;

import slf4d;
import slf4d.default_provider;
import slf4d.provider;

import botan.cert.x509.x509cert;
import botan.pubkey.algo.rsa;

import plist;

import provision;

import imobiledevice;

import server.appleaccount;
import server.developersession;
import version_string;

import sideload;
import sideload.bundle;
import sideload.application;
import sideload.certificateidentity;
import sideload.sign;

import argparse;

import app;
import utils;

version = X509;

noreturn wrongArgument(string msg) {
    getLogger().error(msg);
    exit(1);
}

auto openApp(string path) {
    if (!file.exists(path))
        return wrongArgument("The specified app file does not exist.");

    if (!path.endsWith(".ipa"))
        return wrongArgument("The app is not an ipa file.");

    if (!file.isFile(path))
        return wrongArgument("The app should be an ipa file.");

    return new Application(path);
}

auto openAppFolder(string path) {
    if (!file.exists(path))
        return wrongArgument("The specified app file does not exist.");

    if (file.isFile(path))
        return wrongArgument("The app should be a folder.");

    return new Application(path);
}


auto readFile(string path) {
    return cast(ubyte[]) file.read(path);
}

auto readPrivateKey(string path) {
    RandomNumberGenerator rng = RandomNumberGenerator.makeRng();
    return RSAPrivateKey(loadKey(path, rng));
}

auto readCertificate(string path) {
    return X509Certificate(path, false);
}

extern(C) char* getpass(const(char)* prompt);

string readPasswordLine(string prompt) {
    version (Windows) {
        write(prompt.toStringz(), " [/!\\ The password will appear in clear text in the terminal]: ");
        return readln().chomp();
    } else {
        return fromStringz(cast(immutable) getpass(prompt.toStringz()));
    }
}

string accountSessionPath(string configurationPath) {
    return configurationPath.buildPath("account.plist");
}

void saveAccountSession(string configurationPath, DeveloperSession session) {
    auto log = getLogger();
    try {
        if (!file.exists(configurationPath)) {
            file.mkdirRecurse(configurationPath);
        }
        auto path = accountSessionPath(configurationPath);
        auto pl = dict(
            "appleId", session.appleId().pl,
            "adsid", session.accountIdentityId().pl,
            "token", session.accountGsToken().pl,
        );
        file.write(path, pl.toXml());
        version (Posix) {
            import std.conv : octal;
            file.setAttributes(path, octal!600);
        }
        log.infoF!"Saved Apple ID session for %s. Later installs can skip the password prompt."(session.appleId());
    } catch (Exception e) {
        log.warnF!"Could not save Apple ID session: %s"(e.msg);
    }
}

DeveloperSession loadAccountSession(Device device, ADI adi, string configurationPath) {
    auto log = getLogger();
    auto path = accountSessionPath(configurationPath);
    if (!file.exists(path)) {
        return null;
    }
    try {
        auto pl = Plist.fromXml(cast(string) file.read(path)).dict();
        auto appleId = pl["appleId"].str().native();
        auto adsid = pl["adsid"].str().native();
        auto token = pl["token"].str().native();
        log.infoF!"Restoring saved Apple ID session for %s..."(appleId);
        auto session = DeveloperSession.restore(device, adi, appleId, adsid, token);
        log.debug_("Checking saved session with Apple...");
        auto ping = session.listTeams();
        return ping.match!(
            (DeveloperTeam[] _) {
                log.info("Saved session is still valid.");
                return session;
            },
            (DeveloperPortalError err) {
                log.warnF!"Saved session is no longer valid (%s). You will need to log in again."(err.description);
                file.remove(path);
                return cast(DeveloperSession) null;
            }
        );
    } catch (Exception e) {
        log.warnF!"Could not restore Apple ID session: %s"(e.msg);
        return null;
    }
}

DeveloperSession login(Device device, ADI adi, bool interactive, string configurationPath) {
    auto log = getLogger();

    log.info("Logging in...");

    if (auto saved = loadAccountSession(device, adi, configurationPath)) {
        return saved;
    }

    if (!interactive) {
        log.error("You are not logged in. (add `-i` once to enter your Apple ID; it will be remembered afterwards)");
        return null;
    }

    log.info("Please enter your account informations. They will only be sent to Apple servers.");
    log.info("See it for yourself at https://github.com/Dadoum/Sideloader/");

    write("Apple ID: ");
    string appleId = readln().chomp();
    string password = readPasswordLine("Password: ");

    auto session = DeveloperSession.login(
        device,
        adi,
        appleId,
        password,
        (sendCode, submitCode) {
            sendCode();
            string code;
            do {
                write("A code has been sent to your devices, please type it here (type `resend` to resend one): ");
                code = readln().chomp();
                if (code == "resend") {
                    sendCode();
                    continue;
                }
            } while (submitCode(code).match!((Success _) => false, (ReloginNeeded _) => false, (AppleLoginError _) => true));
        })
    .match!(
        (DeveloperSession s) => s,
        (AppleLoginError error) {
            log.errorF!"Can't log-in! %s (%d)"(error.description, error);
            return cast(DeveloperSession) null;
        }
    );
    if (session) {
        saveAccountSession(configurationPath, session);
    }
    return session;
}

auto initializeADI(string configurationPath)
{
    scope log = getLogger();
    if (!(file.exists(configurationPath.buildPath("lib/libstoreservicescore.so")) && file.exists(configurationPath.buildPath("lib/libCoreADI.so")))) {
        auto succeeded = downloadAndInstallDeps(configurationPath, (progress) {
            write(format!"%.2f %% completed\r"(progress * 100));
            stdout.flush();

            return false;
        });

        if (!succeeded) {
            log.error("Download failed.");
            exit(1);
        }
        log.info("Download completed.");
    }

    scope provisioningData = app.initializeADI(configurationPath);
    return provisioningData;
}

string systemConfigurationPath()
{
    return environment.get("SIDELOADER_CONFIG_DIR").orDefault(defaultConfigurationPath());
}

string defaultConfigurationPath()
{
    version (Windows) {
        string configurationPath = environment["AppData"];
    } else version (OSX) {
        string configurationPath = "~/Library/Preferences/".expandTilde();
    } else {
        string configurationPath = environment.get("XDG_CONFIG_DIR")
            .orDefault("~/.config")
            .expandTilde();
    }
    return configurationPath.buildPath("Sideloader");
}

// planned commands

import app_id;
import certificate;
import device;
import install;
// @(Command("login").Description("Log-in to your Apple account."))
// @(Command("logout").Description("Log-out."))
import sign;
// @(Command("swift-setup").Description("Set-up certificates to build a Swift Package Manager iOS application (requires SPM in the path)."))
import team;
import tool;
// @(Command("tweak").Description("Install a tweak in an ipa file."))

mixin template LoginCommand()
{
    import provision;
    @(NamedArgument("i", "interactive").Description("Prompt to type passwords if needed."))
    bool interactive = false;

    final auto login(Device device, ADI adi) => cli_frontend.login(device, adi, interactive, systemConfigurationPath());
}

@(Command("version").Description("Print the version."))
struct VersionCommand {
    int opCall() {
        writeln(versionStr);
        return 0;
    }
}

int entryPoint(Commands commands)
{
    version (linux) {
        import core.stdc.locale;
        setlocale(LC_ALL, "");
    }

    defaultPoolThreads = commands.threadCount;
    configureLoggingProvider(new shared DefaultProvider(true, commands.debug_ ? Levels.TRACE : Levels.INFO));

    try
    {
        return commands.cmd.match!(
                (AppIdCommand cmd) => cmd(),
                (CertificateCommand cmd) => cmd(),
                (DeviceCommand cmd) => cmd(),
                (InstallCommand cmd) => cmd(),
                (SignCommand cmd) => cmd(),
                (TrollsignCommand cmd) => cmd(),
                (TeamCommand cmd) => cmd(),
                (ToolCommand cmd) => cmd(),
                (VersionCommand cmd) => cmd(),
        );
    }
    catch (Exception ex)
    {
        getLogger().errorF!"%s at %s:%d: %s"(typeid(ex).name, ex.file, ex.line, ex.msg);
        getLogger().debugF!"Full exception: %s"(ex);
        return 1;
    }
}

struct Commands
{
    @(NamedArgument("d", "debug").Description("Enable debug logging"))
    bool debug_;

    @(NamedArgument("thread-count").Description("Numbers of threads to be used for signing the application bundle"))
    uint threadCount = uint.max;

    @SubCommands
    SumType!(AppIdCommand, CertificateCommand, DeviceCommand, InstallCommand, SignCommand, TrollsignCommand, TeamCommand, ToolCommand, VersionCommand) cmd;
}

mixin CLI!Commands.main!entryPoint;

