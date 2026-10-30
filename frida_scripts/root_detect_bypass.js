/*
 * root_detect_bypass.js — Root/jailbreak detection bypass
 * Platform: Android + iOS
 * Purpose:  Prevent the app from detecting root/jailbreak and refusing to run
 * MASVS:   MASVS-RESILIENCE-1
 *
 * Hooks: File.exists, Runtime.exec, RootBeer, SafetyNet (Android);
 *        NSFileManager, canOpenURL, fork/system, IOSSecuritySuite (iOS)
 */

"use strict";

var _TAG = "root_bypass";

function _send(check, path, detail) {
    send({ type: "root_bypass", check: check, path: path || "", status: "bypassed", detail: detail || "" });
}

// ── Android ────────────────────────────────────────────────────────────

if (Java.available) {
    Java.perform(function () {

        var ROOT_PATHS = [
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su", "/su/bin",
            "/system/xbin/busybox", "/sbin/busybox",
            "/system/bin/busybox", "/data/local/xbin/busybox",
            "/system/app/SuperSU", "/system/app/SuperSU.apk",
            "/system/etc/init.d/99telecominfra",
            "/dev/com.koushikdutta.superuser.daemon",
            "/system/xbin/daemonsu",
            // Magisk paths
            "/sbin/.magisk", "/sbin/.core", "/data/adb/magisk",
            "/data/adb/modules", "/system/addon.d/99-magisk.sh",
            "/cache/.disable_magisk",
        ];

        var ROOT_PACKAGES = [
            "com.topjohnwu.magisk", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser",
            "com.noshufou.android.su", "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine", "com.amphoras.hidemyroot",
            "de.robv.android.xposed.installer", "io.github.huskydg.magisk",
        ];

        var ROOT_COMMANDS = ["su", "which su", "id", "busybox", "magisk"];

        // 1. java.io.File.exists — filter root indicator paths
        try {
            var File = Java.use("java.io.File");
            File.exists.implementation = function () {
                var path = this.getAbsolutePath().toString();
                for (var i = 0; i < ROOT_PATHS.length; i++) {
                    if (path.indexOf(ROOT_PATHS[i]) !== -1) {
                        _send("file_check", path, "File.exists → false");
                        return false;
                    }
                }
                return this.exists();
            };
        } catch (e) { /* skip */ }

        // 2. Runtime.exec — filter root detection commands
        try {
            var Runtime = Java.use("java.lang.Runtime");
            // String overload
            Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
                var cmdStr = cmd ? cmd.toString().toLowerCase() : "";
                for (var i = 0; i < ROOT_COMMANDS.length; i++) {
                    if (cmdStr.indexOf(ROOT_COMMANDS[i]) !== -1) {
                        _send("exec_check", cmdStr, "Runtime.exec → IOException");
                        throw Java.use("java.io.IOException").$new("Cannot run program: " + cmd);
                    }
                }
                return this.exec(cmd);
            };
            // String[] overload
            Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
                if (cmds && cmds.length > 0) {
                    var first = cmds[0] ? cmds[0].toString().toLowerCase() : "";
                    for (var i = 0; i < ROOT_COMMANDS.length; i++) {
                        if (first.indexOf(ROOT_COMMANDS[i]) !== -1) {
                            _send("exec_check", first, "Runtime.exec(String[]) → IOException");
                            throw Java.use("java.io.IOException").$new("Cannot run program");
                        }
                    }
                }
                return this.exec(cmds);
            };
        } catch (e) { /* skip */ }

        // 3. PackageManager.getPackageInfo — hide root packages
        try {
            var PM = Java.use("android.app.ApplicationContext");
        } catch (e) { /* skip */ }
        try {
            var PackageManager = Java.use("android.app.ApplicationPackageManager");
            PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (name, flags) {
                for (var i = 0; i < ROOT_PACKAGES.length; i++) {
                    if (name.toString() === ROOT_PACKAGES[i]) {
                        _send("package_check", name.toString(), "getPackageInfo → NameNotFoundException");
                        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(name);
                    }
                }
                return this.getPackageInfo(name, flags);
            };
        } catch (e) { /* skip */ }

        // 4. System.getProperty — hide ro.debuggable, ro.secure
        try {
            var System = Java.use("java.lang.System");
            System.getProperty.overload("java.lang.String").implementation = function (key) {
                if (key === "ro.debuggable") {
                    _send("prop_check", key, "System.getProperty → 0");
                    return "0";
                }
                if (key === "ro.secure") {
                    _send("prop_check", key, "System.getProperty → 1");
                    return "1";
                }
                return this.getProperty(key);
            };
        } catch (e) { /* skip */ }

        // 5. Build.TAGS — hide test-keys
        try {
            var Build = Java.use("android.os.Build");
            var tags = Build.TAGS.value;
            if (tags && tags.toString().indexOf("test-keys") !== -1) {
                Build.TAGS.value = "release-keys";
                _send("build_tags", "test-keys → release-keys", "Build.TAGS replaced");
            }
        } catch (e) { /* skip */ }

        // 6. RootBeer library
        try {
            var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
            var rbMethods = ["isRooted", "isRootedWithoutBusyBoxCheck",
                "detectRootManagementApps", "detectPotentiallyDangerousApps",
                "detectTestKeys", "checkForBusyBoxBinary",
                "checkForSuBinary", "checkSuExists",
                "checkForRWPaths", "checkForDangerousProps",
                "checkForRootNative", "detectRootCloakingApps",
                "isSelinuxFlagInEnabled", "checkForMagiskBinary"];
            rbMethods.forEach(function (m) {
                try {
                    RootBeer[m].implementation = function () {
                        _send("rootbeer", m, "RootBeer." + m + " → false");
                        return false;
                    };
                } catch (e2) { /* method not in this version */ }
            });
        } catch (e) { /* RootBeer not present */ }

        // 7. SafetyNet / Play Integrity
        try {
            var SafetyNet = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
            if (SafetyNet.attest) {
                _send("safetynet", "", "SafetyNet.attest detected (cannot bypass server-side)");
            }
        } catch (e) { /* not present */ }

        // 8. ProcessBuilder — filter root commands
        try {
            var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
            ProcessBuilder.start.implementation = function () {
                var cmdList = this.command();
                if (cmdList && cmdList.size() > 0) {
                    var first = cmdList.get(0).toString().toLowerCase();
                    for (var i = 0; i < ROOT_COMMANDS.length; i++) {
                        if (first.indexOf(ROOT_COMMANDS[i]) !== -1) {
                            _send("exec_check", first, "ProcessBuilder.start → IOException");
                            throw Java.use("java.io.IOException").$new("Cannot run program");
                        }
                    }
                }
                return this.start();
            };
        } catch (e) { /* skip */ }
    });
}

// ── iOS ────────────────────────────────────────────────────────────────

if (ObjC.available) {

    var JB_PATHS = [
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Applications/Installer.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
        "/usr/bin/ssh", "/private/var/lib/apt",
        "/private/var/lib/cydia", "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/var/cache/apt", "/var/lib/apt", "/var/lib/cydia",
        "/var/log/syslog", "/usr/libexec/cydia",
        "/usr/bin/cycript", "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/var/binpack", "/var/checkra1n.dmg",
        "/.bootstrapped_electra", "/.installed_unc0ver",
        "/jb/lzma", "/jb/offsets.plist",
        "/private/var/containers/Bundle/tweaksupport",
    ];

    var JB_URLS = ["cydia://", "sileo://", "zbra://", "filza://", "undecimus://"];

    // 1. NSFileManager.fileExistsAtPath:
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter: function (args) {
                this._path = ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < JB_PATHS.length; i++) {
                    if (this._path.indexOf(JB_PATHS[i]) !== -1) {
                        retval.replace(ptr(0)); // NO
                        _send("file_check", this._path, "fileExistsAtPath → NO");
                        return;
                    }
                }
            }
        });
    } catch (e) { /* skip */ }

    // 2. UIApplication.canOpenURL: — block jailbreak URL schemes
    try {
        var UIApp = ObjC.classes.UIApplication;
        Interceptor.attach(UIApp["- canOpenURL:"].implementation, {
            onEnter: function (args) {
                this._url = ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < JB_URLS.length; i++) {
                    if (this._url.indexOf(JB_URLS[i]) !== -1) {
                        retval.replace(ptr(0)); // NO
                        _send("url_check", this._url, "canOpenURL → NO");
                        return;
                    }
                }
            }
        });
    } catch (e) { /* skip */ }

    // 3. stat / lstat — hide jailbreak paths at syscall level
    try {
        var statAddr = Module.findExportByName(null, "stat");
        if (statAddr) {
            Interceptor.attach(statAddr, {
                onEnter: function (args) {
                    this._path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this._path) {
                        for (var i = 0; i < JB_PATHS.length; i++) {
                            if (this._path.indexOf(JB_PATHS[i]) !== -1) {
                                retval.replace(ptr(-1));
                                _send("stat_check", this._path, "stat → -1");
                                return;
                            }
                        }
                    }
                }
            });
        }
    } catch (e) { /* skip */ }

    // 4. fork() — some apps check if fork succeeds (only works on jailbroken)
    try {
        var forkAddr = Module.findExportByName(null, "fork");
        if (forkAddr) {
            Interceptor.attach(forkAddr, {
                onLeave: function (retval) {
                    retval.replace(ptr(-1)); // pretend fork failed
                    _send("fork_check", "", "fork → -1");
                }
            });
        }
    } catch (e) { /* skip */ }

    // 5. system() — block command execution detection
    try {
        var systemAddr = Module.findExportByName(null, "system");
        if (systemAddr) {
            Interceptor.replace(systemAddr, new NativeCallback(function (cmd) {
                var cmdStr = cmd ? cmd.readUtf8String() : "";
                _send("system_check", cmdStr, "system() → blocked");
                return -1;
            }, "int", ["pointer"]));
        }
    } catch (e) { /* skip */ }

    // 6. IOSSecuritySuite
    try {
        var classes = ObjC.enumerateLoadedClassesSync();
        var issKeys = Object.keys(classes).filter(function (c) {
            return c.indexOf("IOSSecuritySuite") !== -1;
        });
        issKeys.forEach(function (cls) {
            try {
                var obj = ObjC.classes[cls];
                var methods = obj.$ownMethods;
                methods.forEach(function (m) {
                    if (m.indexOf("isJailbroken") !== -1 || m.indexOf("amIJailbroken") !== -1 ||
                        m.indexOf("isRunInEmulator") !== -1 || m.indexOf("amIRunInEmulator") !== -1 ||
                        m.indexOf("amIDebugged") !== -1 || m.indexOf("isDebugged") !== -1 ||
                        m.indexOf("amIReverseEngineered") !== -1 || m.indexOf("amITampered") !== -1) {
                        Interceptor.attach(obj[m].implementation, {
                            onLeave: function (retval) {
                                retval.replace(ptr(0)); // false
                                _send("iss", m, cls + "." + m + " → false");
                            }
                        });
                    }
                });
            } catch (e2) { /* skip */ }
        });
    } catch (e) { /* skip */ }

    // 7. dyld image count — hide injected dylibs
    try {
        var dyldCountAddr = Module.findExportByName(null, "_dyld_image_count");
        // Note: modifying this can crash; just log for awareness
        if (dyldCountAddr) {
            Interceptor.attach(dyldCountAddr, {
                onLeave: function (retval) {
                    // Log but don't modify — too dangerous
                    _send("dyld_check", retval.toInt32().toString(), "_dyld_image_count called (not modified)");
                }
            });
        }
    } catch (e) { /* skip */ }
}

send({ type: "root_bypass", check: "init", path: "", status: "loaded", detail: "Root/jailbreak bypass hooks installed" });
