module install;

import slf4d;
import slf4d.default_provider;

import argparse;
import progress;
import std.exception;
import std.stdio : writefln;

import imobiledevice;

import sideload;
import sideload.application;

import cli_frontend;

@(Command("install").Description("Install an application on the device (renames the app, register the identifier, sign and install automatically)."))
struct InstallCommand
{
    mixin LoginCommand;

    @(PositionalArgument(0, "app path").Description("The path of the IPA file to sideload."))
    string appPath;

    @(NamedArgument("udid").Description("UDID of the device (if multiple are available)."))
    string udid = null;

    @(NamedArgument("team").Description("Apple Developer Team ID to use for signing."))
    string teamId = null;

    @(NamedArgument("new-certificate").Description("Create a new signing certificate instead of reusing a saved one."))
    bool newCertificate = false;

    @(NamedArgument("reuse-certificate").Description("Require the saved certificate for the selected team; do not create a replacement."))
    bool reuseCertificate = false;

    @(NamedArgument("gsv").Description("Emit machine-readable progress events for the GSV user interface."))
    bool gsv = false;

    @(NamedArgument("singlethread").Description("Run the signature process on a single thread. Sacrifices speed for more consistency."))
    bool singlethreaded = true;

    int opCall()
    {
        enforce(!(newCertificate && reuseCertificate), "--new-certificate and --reuse-certificate cannot be used together.");
        Application app = openApp(appPath);

        auto log = getLogger();

        string configurationPath = systemConfigurationPath();

        scope provisioningData = initializeADI(configurationPath);
        scope adi = provisioningData.adi;
        scope akDevice = provisioningData.device;

        auto appleAccount = login(akDevice, adi);

        if (!appleAccount) {
            return 1;
        }

        auto devices = iDevice.deviceList();
        string udid = this.udid;
        if (!udid) {
            if (devices.length == 1) {
                udid = devices[0].udid;
            } else {
                if (!devices.length) {
                    log.error("No device connected.");
                    return 1;
                }
                if (!this.udid) {
                    log.error("Multiple devices are connected. Please select one with --udid.");
                }
            }
        }

        log.infoF!"Initiating connection the device (UUID: %s)"(udid);
        auto device = new iDevice(udid);
        Bar progressBar;
        string message;
        if (!gsv) {
            progressBar = new Bar();
            progressBar.message = () => message;
        }
        sideloadFull(configurationPath, device, appleAccount, app, (progress, action) {
            if (gsv) {
                writefln!"GSV_PROGRESS\t%d\t%s"(cast(int) (progress * 100), action);
            } else {
                message = action;
                progressBar.index = cast(int) (progress * 100);
                progressBar.update();
            }
        }, !singlethreaded, teamId, !newCertificate, reuseCertificate);
        if (!gsv) {
            progressBar.finish();
        }

        return 0;
    }
}
