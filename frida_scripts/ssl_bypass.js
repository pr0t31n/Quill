/*
 * ssl_bypass.js — Universal SSL/TLS certificate pinning bypass
 * Platform: Android + iOS
 * Purpose:  Bypass certificate pinning so MITM proxy can intercept traffic
 * MASVS:   MASVS-NETWORK-1, MASVS-NETWORK-2
 *
 * Hooks: TrustManagerImpl, X509TrustManager, OkHttp CertificatePinner,
 *        Flutter, React Native (Android); SecTrust*, SSLHandshake,
 *        AFNetworking, Alamofire, TrustKit (iOS)
 */

"use strict";

var _TAG = "ssl_bypass";

function _send(host, detail) {
    send({ type: "ssl_bypass", host: host || "*", status: "bypassed", detail: detail });
}

// ── Android ────────────────────────────────────────────────────────────

if (Java.available) {
    Java.perform(function () {

        // 1. TrustManagerImpl.checkTrustedRecursive (Android 7+)
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            var checkTrusted = TrustManagerImpl.checkTrustedRecursive;
            if (checkTrusted) {
                checkTrusted.implementation = function () {
                    _send("", "TrustManagerImpl.checkTrustedRecursive");
                    return Java.use("java.util.ArrayList").$new();
                };
            }
        } catch (e) { /* class not present */ }

        // 2. Generic X509TrustManager.checkServerTrusted
        try {
            var X509TM = Java.use("javax.net.ssl.X509TrustManager");
            var TMFactory = Java.use("javax.net.ssl.TrustManagerFactory");
            // Hook all TrustManager implementations found at runtime
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        Java.classFactory.loader = loader;
                        Java.use("javax.net.ssl.X509TrustManager");
                    } catch (e) { /* skip */ }
                },
                onComplete: function () {}
            });
        } catch (e) { /* skip */ }

        // Direct hook on the interface default implementations
        try {
            var TrustMgr = Java.use("javax.net.ssl.X509TrustManager");
            // Can't hook interface directly; hook known platform impl
            var PlatformTM = Java.use("com.android.org.conscrypt.Platform");
            if (PlatformTM.checkServerTrusted) {
                PlatformTM.checkServerTrusted.overload("javax.net.ssl.X509TrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "com.android.org.conscrypt.AbstractConscryptSocket").implementation = function (tm, chain, authType, socket) {
                    _send("", "Platform.checkServerTrusted");
                };
            }
        } catch (e) { /* not all devices have this */ }

        // 3. OkHttp3 CertificatePinner.check
        try {
            var CertPinner = Java.use("okhttp3.CertificatePinner");
            // check$okhttp (Kotlin-mangled) or check(String, List)
            var methods = CertPinner.class.getDeclaredMethods();
            for (var i = 0; i < methods.length; i++) {
                var name = methods[i].getName();
                if (name === "check" || name === "check$okhttp") {
                    try {
                        CertPinner[name].overload("java.lang.String", "java.util.List").implementation = function (hostname) {
                            _send(hostname ? hostname.toString() : "", "OkHttp3.CertificatePinner.check");
                        };
                    } catch (e2) { /* overload mismatch */ }
                    try {
                        CertPinner[name].overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (hostname) {
                            _send(hostname ? hostname.toString() : "", "OkHttp3.CertificatePinner.check$okhttp");
                        };
                    } catch (e2) { /* overload mismatch */ }
                }
            }
        } catch (e) { /* OkHttp not present */ }

        // 4. OkHttp legacy (com.squareup.okhttp)
        try {
            var LegacyPinner = Java.use("com.squareup.okhttp.CertificatePinner");
            LegacyPinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname) {
                _send(hostname ? hostname.toString() : "", "OkHttp-legacy.CertificatePinner.check");
            };
        } catch (e) { /* not present */ }

        // 5. Conscrypt / BoringSSL (used by newer Android + Flutter)
        try {
            var ConscryptTM = Java.use("org.conscrypt.ConscryptFileDescriptorSocket");
            ConscryptTM.verifyCertificateChain.implementation = function (certRefs, authMethod) {
                _send("", "Conscrypt.verifyCertificateChain");
            };
        } catch (e) { /* skip */ }

        // 6. Flutter BoringSSL native hook
        try {
            var flutterMod = Process.findModuleByName("libflutter.so");
            if (flutterMod) {
                // ssl_crypto_x509_session_verify_cert_chain
                var symbols = flutterMod.enumerateExports();
                for (var s = 0; s < symbols.length; s++) {
                    if (symbols[s].name.indexOf("session_verify_cert_chain") !== -1) {
                        Interceptor.attach(symbols[s].address, {
                            onLeave: function (retval) {
                                retval.replace(0x1);
                                _send("", "Flutter.session_verify_cert_chain");
                            }
                        });
                        break;
                    }
                }
            }
        } catch (e) { /* Flutter not loaded */ }

        // 7. React Native (OkHttp underneath, already covered; also TLS factory)
        try {
            var RNNetworking = Java.use("com.facebook.react.modules.network.OkHttpClientProvider");
            // Hook getOkHttpClient to inject permissive TrustManager later
            // (OkHttp hooks above handle the actual pin check)
        } catch (e) { /* RN not present */ }

        // 8. WebView SSL error handler — accept all
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
                handler.proceed();
                _send("", "WebViewClient.onReceivedSslError.proceed");
            };
        } catch (e) { /* skip */ }

        // 9. SSLContext.init — inject permissive TrustManager
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (km, tm, sr) {
                var PermissiveTM = Java.registerClass({
                    name: "com.quill.PermissiveTrustManager",
                    implements: [Java.use("javax.net.ssl.X509TrustManager")],
                    methods: {
                        checkClientTrusted: function () {},
                        checkServerTrusted: function () {
                            _send("", "SSLContext.init.PermissiveTrustManager");
                        },
                        getAcceptedIssuers: function () {
                            return [];
                        }
                    }
                });
                var tmArr = Java.array("javax.net.ssl.TrustManager", [PermissiveTM.$new()]);
                this.init(km, tmArr, sr);
            };
        } catch (e) { /* skip */ }

        // 10. HttpsURLConnection.setDefaultHostnameVerifier — accept all
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            var PermissiveHV = Java.registerClass({
                name: "com.quill.PermissiveHostnameVerifier",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function (hostname) {
                        _send(hostname ? hostname.toString() : "", "HostnameVerifier.verify");
                        return true;
                    }
                }
            });
            HttpsURLConnection.setDefaultHostnameVerifier(PermissiveHV.$new());
        } catch (e) { /* skip */ }
    });
}

// ── iOS ────────────────────────────────────────────────────────────────

if (ObjC.available) {

    // 1. SecTrustEvaluate
    try {
        var SecTrustEvaluate = new NativeFunction(
            Module.findExportByName("Security", "SecTrustEvaluate"),
            "int", ["pointer", "pointer"]
        );
        Interceptor.replace(Module.findExportByName("Security", "SecTrustEvaluate"), new NativeCallback(function (trust, result) {
            var kSecTrustResultProceed = 1;
            if (result !== null && !result.isNull()) {
                result.writeU32(kSecTrustResultProceed);
            }
            _send("", "SecTrustEvaluate");
            return 0; // errSecSuccess
        }, "int", ["pointer", "pointer"]));
    } catch (e) { /* skip */ }

    // 2. SecTrustEvaluateWithError (iOS 12+)
    try {
        var addr = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (addr) {
            Interceptor.replace(addr, new NativeCallback(function (trust, error) {
                if (error !== null && !error.isNull()) {
                    error.writePointer(ptr(0)); // no error
                }
                _send("", "SecTrustEvaluateWithError");
                return 1; // true = trusted
            }, "bool", ["pointer", "pointer"]));
        }
    } catch (e) { /* skip */ }

    // 3. SecTrustEvaluateAsync
    try {
        var asyncAddr = Module.findExportByName("Security", "SecTrustEvaluateAsync");
        if (asyncAddr) {
            Interceptor.attach(asyncAddr, {
                onEnter: function (args) {
                    // We can't easily replace the async callback;
                    // just note the call for logging
                },
                onLeave: function (retval) {
                    _send("", "SecTrustEvaluateAsync (noted)");
                }
            });
        }
    } catch (e) { /* skip */ }

    // 4. SSLSetPeerDomainName + SSLHandshake (legacy)
    try {
        var sslHandshake = Module.findExportByName("Security", "SSLHandshake");
        if (sslHandshake) {
            Interceptor.attach(sslHandshake, {
                onLeave: function (retval) {
                    retval.replace(0); // noErr
                    _send("", "SSLHandshake");
                }
            });
        }
    } catch (e) { /* skip */ }

    // 5. AFNetworking — setSSLPinningMode:
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy["- setSSLPinningMode:"].implementation, {
                onEnter: function (args) {
                    // Force AFSSLPinningModeNone = 0
                    args[2] = ptr(0);
                    _send("", "AFNetworking.setSSLPinningMode → None");
                }
            });
            // Also hook evaluateServerTrust:forDomain:
            try {
                Interceptor.attach(AFSecurityPolicy["- evaluateServerTrust:forDomain:"].implementation, {
                    onLeave: function (retval) {
                        retval.replace(ptr(1)); // YES
                        _send("", "AFSecurityPolicy.evaluateServerTrust → YES");
                    }
                });
            } catch (e2) { /* method not found */ }
        }
    } catch (e) { /* AFNetworking not present */ }

    // 6. Alamofire ServerTrustEvaluating
    try {
        var classes = ObjC.enumerateLoadedClassesSync();
        var alKeys = Object.keys(classes).filter(function (c) {
            return c.indexOf("Alamofire") !== -1 && c.indexOf("ServerTrust") !== -1;
        });
        alKeys.forEach(function (cls) {
            try {
                var obj = ObjC.classes[cls];
                if (obj["- evaluate:forHost:"]) {
                    Interceptor.attach(obj["- evaluate:forHost:"].implementation, {
                        onLeave: function (retval) {
                            retval.replace(ptr(1));
                            _send("", "Alamofire." + cls + ".evaluate → YES");
                        }
                    });
                }
            } catch (e2) { /* skip */ }
        });
    } catch (e) { /* skip */ }

    // 7. TrustKit — verifyPublicKeyPin:
    try {
        var TrustKit = ObjC.classes.TSKPinningValidator;
        if (TrustKit && TrustKit["+ evaluateTrust:forHostname:withPins:"]) {
            Interceptor.attach(TrustKit["+ evaluateTrust:forHostname:withPins:"].implementation, {
                onLeave: function (retval) {
                    retval.replace(ptr(0)); // TSKTrustEvaluationSuccess
                    _send("", "TrustKit.evaluateTrust → Success");
                }
            });
        }
    } catch (e) { /* TrustKit not present */ }

    // 8. NSURLSession challenge — accept all
    try {
        var resolver = ObjC.classes.NSURLSession;
        // Hook the delegate callback at the lower level
        Interceptor.attach(ObjC.classes.__NSCFURLSessionConnection["- _]_]_onChallenge:disposition:credential:"].implementation || ptr(0), {
            onEnter: function () { /* skip non-existent */ }
        });
    } catch (e) { /* handled by SecTrust hooks above */ }

    // 9. BoringSSL (used by iOS apps via Network.framework)
    try {
        var boringMod = Process.findModuleByName("libboringssl.dylib");
        if (boringMod) {
            var symbols = boringMod.enumerateExports();
            for (var i = 0; i < symbols.length; i++) {
                if (symbols[i].name === "SSL_get_psk_identity") {
                    // Hook SSL_CTX_set_custom_verify if available
                    break;
                }
            }
            var customVerify = Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify");
            if (customVerify) {
                Interceptor.attach(customVerify, {
                    onEnter: function (args) {
                        // args[2] is the callback — replace with one that returns ssl_verify_ok
                        var ok_cb = new NativeCallback(function () {
                            _send("", "BoringSSL.custom_verify → ok");
                            return 0; // ssl_verify_ok
                        }, "int", ["pointer", "pointer"]);
                        args[2] = ok_cb;
                    }
                });
            }
        }
    } catch (e) { /* skip */ }
}

send({ type: "ssl_bypass", host: "*", status: "loaded", detail: "SSL pinning bypass hooks installed" });
