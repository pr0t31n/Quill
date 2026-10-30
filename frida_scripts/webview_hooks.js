(function() {
    'use strict';

    var CATALOGUE_ID = 'QUILL-INS-008';

    function emitFinding(title, severity, description, data) {
        send({
            type: 'finding',
            title: title,
            severity: severity,
            catalogue_id: CATALOGUE_ID,
            description: description,
            data: data
        });
    }

    function emitLog(message) {
        send({ type: 'log', message: message });
    }

    function getCallerClass() {
        try {
            var stack = Java.use('java.lang.Thread').currentThread().getStackTrace();
            for (var i = 0; i < stack.length && i < 20; i++) {
                var cls = stack[i].getClassName();
                if (cls.indexOf('android.webkit') === -1 &&
                    cls.indexOf('java.lang.reflect') === -1 &&
                    cls.indexOf('java.lang.Thread') === -1) {
                    return cls;
                }
            }
        } catch (e) { /* ignore */ }
        return 'unknown';
    }

    // ── Android hooks ──

    if (Java && Java.available) {
        Java.perform(function() {
            emitLog('[webview_hooks] Attaching Android WebView hooks');

            // WebView.loadUrl(String)
            try {
                var WebView = Java.use('android.webkit.WebView');
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    try {
                        var urlStr = url ? url.toString() : '';
                        var caller = getCallerClass();
                        emitLog('[webview_hooks] WebView.loadUrl | url: ' + urlStr + ' | caller: ' + caller);

                        if (urlStr.indexOf('http://') === 0) {
                            emitFinding(
                                'WebView Loads HTTP URL (Cleartext)',
                                'HIGH',
                                'The application loads an HTTP URL in a WebView: ' + urlStr +
                                '. This exposes content to man-in-the-middle attacks.',
                                { platform: 'android', component: 'WebView', method: 'loadUrl',
                                  url: urlStr, caller: caller, cleartext: true }
                            );
                        }

                        if (urlStr.toLowerCase().indexOf('javascript:') === 0) {
                            emitLog('[webview_hooks] JavaScript execution via loadUrl: ' +
                                    urlStr.substring(0, 200));
                        }

                        if (urlStr.indexOf('file://') === 0) {
                            emitFinding(
                                'WebView Loads Local File',
                                'MEDIUM',
                                'The application loads a local file in a WebView: ' + urlStr +
                                '. Combined with JavaScript and file access this could allow reading local files.',
                                { platform: 'android', component: 'WebView', method: 'loadUrl',
                                  url: urlStr, caller: caller, local_file: true }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in loadUrl hook: ' + e);
                    }
                    return this.loadUrl(url);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook WebView.loadUrl(String): ' + e);
            }

            // WebView.loadUrl(String, Map) — with headers
            try {
                var WebView1b = Java.use('android.webkit.WebView');
                WebView1b.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
                    try {
                        var urlStr = url ? url.toString() : '';
                        emitLog('[webview_hooks] WebView.loadUrl (headers) | url: ' + urlStr);
                        if (urlStr.indexOf('http://') === 0) {
                            emitFinding(
                                'WebView Loads HTTP URL (Cleartext)',
                                'HIGH',
                                'HTTP URL loaded in WebView with custom headers: ' + urlStr,
                                { platform: 'android', component: 'WebView', method: 'loadUrl',
                                  url: urlStr, has_custom_headers: true, cleartext: true }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in loadUrl(headers) hook: ' + e);
                    }
                    return this.loadUrl(url, headers);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook WebView.loadUrl(String, Map): ' + e);
            }

            // WebView.loadData
            try {
                var WebView2 = Java.use('android.webkit.WebView');
                WebView2.loadData.implementation = function(data, mimeType, encoding) {
                    try {
                        var preview = data ? String(data).substring(0, 200) : '';
                        emitLog('[webview_hooks] WebView.loadData | mimeType: ' + mimeType +
                                ' | encoding: ' + encoding + ' | preview: ' + preview);
                    } catch (e) {
                        emitLog('[webview_hooks] Error in loadData hook: ' + e);
                    }
                    return this.loadData(data, mimeType, encoding);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook WebView.loadData: ' + e);
            }

            // WebView.loadDataWithBaseURL
            try {
                var WebView3 = Java.use('android.webkit.WebView');
                WebView3.loadDataWithBaseURL.implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
                    try {
                        emitLog('[webview_hooks] WebView.loadDataWithBaseURL | baseUrl: ' + baseUrl +
                                ' | mimeType: ' + mimeType);
                        if (baseUrl && String(baseUrl).indexOf('http://') === 0) {
                            emitFinding(
                                'WebView loadDataWithBaseURL Uses HTTP Base',
                                'MEDIUM',
                                'HTTP base URL used in loadDataWithBaseURL: ' + baseUrl +
                                '. Relative resource loads will use cleartext.',
                                { platform: 'android', component: 'WebView', method: 'loadDataWithBaseURL',
                                  base_url: String(baseUrl), cleartext: true }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in loadDataWithBaseURL hook: ' + e);
                    }
                    return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook WebView.loadDataWithBaseURL: ' + e);
            }

            // WebView.addJavascriptInterface
            try {
                var WebView4 = Java.use('android.webkit.WebView');
                WebView4.addJavascriptInterface.implementation = function(obj, name) {
                    try {
                        var objClass = obj ? obj.getClass().getName() : 'unknown';
                        emitLog('[webview_hooks] addJavascriptInterface | name: ' + name + ' | class: ' + objClass);
                        emitFinding(
                            'JavaScript Interface Exposed in WebView',
                            'HIGH',
                            'A JavaScript interface "' + name + '" (class: ' + objClass +
                            ') is exposed to WebView content. If untrusted content is loaded, ' +
                            'this interface could be abused to execute native code.',
                            { platform: 'android', component: 'WebView', method: 'addJavascriptInterface',
                              interface_name: String(name), object_class: objClass }
                        );
                    } catch (e) {
                        emitLog('[webview_hooks] Error in addJavascriptInterface hook: ' + e);
                    }
                    return this.addJavascriptInterface(obj, name);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook addJavascriptInterface: ' + e);
            }

            // WebSettings.setJavaScriptEnabled
            try {
                var WebSettings = Java.use('android.webkit.WebSettings');
                WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
                    try {
                        emitLog('[webview_hooks] setJavaScriptEnabled: ' + enabled);
                        if (enabled) {
                            emitFinding(
                                'JavaScript Enabled in WebView',
                                'INFO',
                                'JavaScript is enabled in a WebView. This is common but increases ' +
                                'the attack surface if untrusted content is loaded.',
                                { platform: 'android', component: 'WebSettings',
                                  setting: 'setJavaScriptEnabled', value: true }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in setJavaScriptEnabled hook: ' + e);
                    }
                    return this.setJavaScriptEnabled(enabled);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook setJavaScriptEnabled: ' + e);
            }

            // WebSettings.setAllowFileAccess
            try {
                var WebSettings2 = Java.use('android.webkit.WebSettings');
                WebSettings2.setAllowFileAccess.implementation = function(allow) {
                    try {
                        emitLog('[webview_hooks] setAllowFileAccess: ' + allow);
                        if (allow) {
                            emitFinding(
                                'File Access Enabled in WebView',
                                'MEDIUM',
                                'setAllowFileAccess(true) enables file:// access in WebView. ' +
                                'Combined with JavaScript this can allow reading local files.',
                                { platform: 'android', component: 'WebSettings',
                                  setting: 'setAllowFileAccess', value: true }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in setAllowFileAccess hook: ' + e);
                    }
                    return this.setAllowFileAccess(allow);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook setAllowFileAccess: ' + e);
            }

            // WebSettings.setAllowUniversalAccessFromFileURLs
            try {
                var WebSettings3 = Java.use('android.webkit.WebSettings');
                WebSettings3.setAllowUniversalAccessFromFileURLs.implementation = function(allow) {
                    try {
                        emitLog('[webview_hooks] setAllowUniversalAccessFromFileURLs: ' + allow);
                        if (allow) {
                            emitFinding(
                                'Universal File Access Enabled in WebView',
                                'CRITICAL',
                                'setAllowUniversalAccessFromFileURLs(true) allows file:// JavaScript ' +
                                'to access content from any origin, bypassing the same-origin policy. ' +
                                'This is a severe security misconfiguration.',
                                { platform: 'android', component: 'WebSettings',
                                  setting: 'setAllowUniversalAccessFromFileURLs', value: true }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in setAllowUniversalAccessFromFileURLs hook: ' + e);
                    }
                    return this.setAllowUniversalAccessFromFileURLs(allow);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook setAllowUniversalAccessFromFileURLs: ' + e);
            }

            // WebSettings.setAllowFileAccessFromFileURLs
            try {
                var WebSettings4 = Java.use('android.webkit.WebSettings');
                WebSettings4.setAllowFileAccessFromFileURLs.implementation = function(allow) {
                    try {
                        emitLog('[webview_hooks] setAllowFileAccessFromFileURLs: ' + allow);
                        if (allow) {
                            emitFinding(
                                'File URL Cross-Access Enabled in WebView',
                                'HIGH',
                                'setAllowFileAccessFromFileURLs(true) allows JavaScript in file:// URLs ' +
                                'to access other file:// URLs.',
                                { platform: 'android', component: 'WebSettings',
                                  setting: 'setAllowFileAccessFromFileURLs', value: true }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in setAllowFileAccessFromFileURLs hook: ' + e);
                    }
                    return this.setAllowFileAccessFromFileURLs(allow);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook setAllowFileAccessFromFileURLs: ' + e);
            }

            // WebSettings.setMixedContentMode
            try {
                var WebSettings5 = Java.use('android.webkit.WebSettings');
                WebSettings5.setMixedContentMode.implementation = function(mode) {
                    try {
                        var modeNames = { 0: 'ALWAYS_ALLOW', 1: 'NEVER_ALLOW', 2: 'COMPATIBILITY' };
                        var modeName = modeNames[mode] || ('mode_' + mode);
                        emitLog('[webview_hooks] setMixedContentMode: ' + modeName);
                        if (mode === 0) {
                            emitFinding(
                                'Mixed Content Always Allowed in WebView',
                                'MEDIUM',
                                'MIXED_CONTENT_ALWAYS_ALLOW permits HTTPS pages to load HTTP resources, ' +
                                'degrading TLS protection.',
                                { platform: 'android', component: 'WebSettings',
                                  setting: 'setMixedContentMode', mode: modeName, value: mode }
                            );
                        }
                    } catch (e) {
                        emitLog('[webview_hooks] Error in setMixedContentMode hook: ' + e);
                    }
                    return this.setMixedContentMode(mode);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook setMixedContentMode: ' + e);
            }

            // WebSettings.setDomStorageEnabled
            try {
                var WebSettings6 = Java.use('android.webkit.WebSettings');
                WebSettings6.setDomStorageEnabled.implementation = function(enabled) {
                    emitLog('[webview_hooks] setDomStorageEnabled: ' + enabled);
                    return this.setDomStorageEnabled(enabled);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook setDomStorageEnabled: ' + e);
            }

            // SslErrorHandler.proceed — app accepts invalid SSL certs
            try {
                var SslHandler = Java.use('android.webkit.SslErrorHandler');
                SslHandler.proceed.implementation = function() {
                    emitLog('[webview_hooks] SslErrorHandler.proceed() called');
                    emitFinding(
                        'WebView Accepts Invalid SSL Certificates',
                        'CRITICAL',
                        'SslErrorHandler.proceed() was called, meaning the application accepts ' +
                        'invalid SSL certificates in WebView. This enables MITM attacks.',
                        { platform: 'android', component: 'SslErrorHandler',
                          method: 'proceed', accepts_invalid_certs: true }
                    );
                    return this.proceed();
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook SslErrorHandler.proceed: ' + e);
            }

            // WebView.evaluateJavascript
            try {
                var WebView5 = Java.use('android.webkit.WebView');
                WebView5.evaluateJavascript.implementation = function(script, callback) {
                    try {
                        var preview = script ? script.toString().substring(0, 200) : '';
                        emitLog('[webview_hooks] evaluateJavascript: ' + preview);
                    } catch (e) { /* ignore */ }
                    return this.evaluateJavascript(script, callback);
                };
            } catch (e) {
                emitLog('[webview_hooks] Failed to hook evaluateJavascript: ' + e);
            }

            emitLog('[webview_hooks] Android WebView hooks attached');
        });
    }

    // ── iOS hooks ──

    if (ObjC && ObjC.available) {
        emitLog('[webview_hooks] Attaching iOS WebView hooks');

        // WKWebView loadRequest:
        try {
            var WKWebView = ObjC.classes.WKWebView;
            if (WKWebView && WKWebView['- loadRequest:']) {
                Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var request = ObjC.Object(args[2]);
                            var url = request.URL().absoluteString().toString();
                            emitLog('[webview_hooks] WKWebView loadRequest: | url: ' + url);
                            if (url.indexOf('http://') === 0) {
                                emitFinding(
                                    'WKWebView Loads HTTP URL (Cleartext)',
                                    'HIGH',
                                    'HTTP URL loaded in WKWebView: ' + url +
                                    '. Content is vulnerable to interception.',
                                    { platform: 'ios', component: 'WKWebView', method: 'loadRequest:',
                                      url: url, cleartext: true }
                                );
                            }
                        } catch (e) {
                            emitLog('[webview_hooks] Error in WKWebView loadRequest: hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[webview_hooks] Failed to hook WKWebView loadRequest: ' + e);
        }

        // WKWebView evaluateJavaScript:completionHandler:
        try {
            var WKWebView2 = ObjC.classes.WKWebView;
            if (WKWebView2 && WKWebView2['- evaluateJavaScript:completionHandler:']) {
                Interceptor.attach(WKWebView2['- evaluateJavaScript:completionHandler:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var script = ObjC.Object(args[2]).toString();
                            var preview = script.length > 200 ? script.substring(0, 200) + '...' : script;
                            emitLog('[webview_hooks] WKWebView evaluateJavaScript: ' + preview);
                        } catch (e) {
                            emitLog('[webview_hooks] Error in evaluateJavaScript hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[webview_hooks] Failed to hook WKWebView evaluateJavaScript: ' + e);
        }

        // WKWebView loadHTMLString:baseURL:
        try {
            var WKWebView3 = ObjC.classes.WKWebView;
            if (WKWebView3 && WKWebView3['- loadHTMLString:baseURL:']) {
                Interceptor.attach(WKWebView3['- loadHTMLString:baseURL:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var baseURL = ObjC.Object(args[3]);
                            var baseURLStr = baseURL.isNull ? 'null' : baseURL.absoluteString().toString();
                            emitLog('[webview_hooks] WKWebView loadHTMLString:baseURL: | base: ' + baseURLStr);
                            if (baseURLStr && baseURLStr.indexOf('http://') === 0) {
                                emitFinding(
                                    'WKWebView HTML Loaded with HTTP Base URL',
                                    'MEDIUM',
                                    'HTML loaded in WKWebView with HTTP base URL: ' + baseURLStr,
                                    { platform: 'ios', component: 'WKWebView',
                                      method: 'loadHTMLString:baseURL:', base_url: baseURLStr, cleartext: true }
                                );
                            }
                        } catch (e) {
                            emitLog('[webview_hooks] Error in loadHTMLString hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[webview_hooks] Failed to hook loadHTMLString:baseURL: ' + e);
        }

        // WKUserContentController.addScriptMessageHandler:name: — JS bridge
        try {
            var WKUCC = ObjC.classes.WKUserContentController;
            if (WKUCC && WKUCC['- addScriptMessageHandler:name:']) {
                Interceptor.attach(WKUCC['- addScriptMessageHandler:name:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var name = ObjC.Object(args[3]).toString();
                            var handler = ObjC.Object(args[2]);
                            var handlerClass = handler.$className;
                            emitLog('[webview_hooks] addScriptMessageHandler | name: ' + name +
                                    ' | handler: ' + handlerClass);
                            emitFinding(
                                'JavaScript Message Handler Exposed in WKWebView',
                                'MEDIUM',
                                'A JavaScript message handler "' + name + '" (class: ' + handlerClass +
                                ') is registered, creating a JS-to-native bridge.',
                                { platform: 'ios', component: 'WKUserContentController',
                                  method: 'addScriptMessageHandler:name:', handler_name: name,
                                  handler_class: handlerClass }
                            );
                        } catch (e) {
                            emitLog('[webview_hooks] Error in addScriptMessageHandler hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[webview_hooks] Failed to hook addScriptMessageHandler: ' + e);
        }

        // WKUserContentController.addUserScript: — injected scripts
        try {
            var WKUCC2 = ObjC.classes.WKUserContentController;
            if (WKUCC2 && WKUCC2['- addUserScript:']) {
                Interceptor.attach(WKUCC2['- addUserScript:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var script = ObjC.Object(args[2]);
                            var src = script.source().toString();
                            var injection = script.injectionTime();
                            var injectName = injection === 0 ? 'atDocumentStart' : 'atDocumentEnd';
                            emitLog('[webview_hooks] addUserScript | injection: ' + injectName +
                                    ' | src: ' + src.substring(0, 200));
                        } catch (e) {
                            emitLog('[webview_hooks] Error in addUserScript hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[webview_hooks] Failed to hook addUserScript: ' + e);
        }

        // Detect deprecated UIWebView
        try {
            var UIWebView = ObjC.classes.UIWebView;
            if (UIWebView) {
                emitFinding(
                    'Deprecated UIWebView Usage Detected',
                    'MEDIUM',
                    'The application includes UIWebView, deprecated since iOS 12. ' +
                    'UIWebView has known security issues and should be replaced with WKWebView.',
                    { platform: 'ios', component: 'UIWebView', deprecated: true }
                );
                if (UIWebView['- loadRequest:']) {
                    Interceptor.attach(UIWebView['- loadRequest:'].implementation, {
                        onEnter: function(args) {
                            try {
                                var request = ObjC.Object(args[2]);
                                var url = request.URL().absoluteString().toString();
                                emitLog('[webview_hooks] UIWebView loadRequest: | url: ' + url);
                            } catch (e) { /* ignore */ }
                        }
                    });
                }
            }
        } catch (e) {
            emitLog('[webview_hooks] UIWebView not present (expected on modern apps)');
        }

        // WKNavigationDelegate decidePolicyForNavigationAction
        try {
            var resolver = new ApiResolver('objc');
            var matches = resolver.enumerateMatches(
                '-[* webView:decidePolicyForNavigationAction:decisionHandler:]');
            matches.forEach(function(match) {
                try {
                    Interceptor.attach(match.address, {
                        onEnter: function(args) {
                            try {
                                var action = ObjC.Object(args[3]);
                                var request = action.request();
                                var url = request.URL().absoluteString().toString();
                                emitLog('[webview_hooks] decidePolicyForNavigationAction | url: ' +
                                        url.substring(0, 200));
                            } catch (e) { /* ignore */ }
                        }
                    });
                } catch (e) { /* ignore */ }
            });
        } catch (e) {
            emitLog('[webview_hooks] Failed to enumerate navigation delegates: ' + e);
        }

        // WKNavigationDelegate SSL/auth challenge handling
        try {
            var authMatches = new ApiResolver('objc').enumerateMatches(
                '-[* webView:didReceiveAuthenticationChallenge:completionHandler:]');
            authMatches.forEach(function(match) {
                try {
                    Interceptor.attach(match.address, {
                        onEnter: function(args) {
                            try {
                                var challenge = ObjC.Object(args[3]);
                                var authMethod = challenge.protectionSpace().authenticationMethod().toString();
                                var host = challenge.protectionSpace().host().toString();
                                emitLog('[webview_hooks] didReceiveAuthenticationChallenge | host: ' +
                                        host + ' | method: ' + authMethod);
                            } catch (e) { /* ignore */ }
                        }
                    });
                } catch (e) { /* ignore */ }
            });
        } catch (e) {
            emitLog('[webview_hooks] Failed to enumerate auth challenge delegates: ' + e);
        }

        emitLog('[webview_hooks] iOS WebView hooks attached');
    }
})();
