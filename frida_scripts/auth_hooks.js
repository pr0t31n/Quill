/*
 * auth_hooks.js — Authentication and token handling monitor
 * Platform: Android + iOS
 * Purpose:  Track where auth tokens are stored, whether encrypted, OAuth flows
 * MASVS:   MASVS-AUTH-1, MASVS-AUTH-2, MASVS-STORAGE-1
 *
 * Hooks: SharedPreferences, AccountManager, WebView OAuth (Android);
 *        NSUserDefaults, Keychain SecItem*, WKWebView (iOS)
 */

"use strict";

var _TAG = "auth_hooks";

var AUTH_KEYS = [
    "token", "access_token", "refresh_token", "auth_token",
    "session", "session_id", "sessionid", "jsessionid",
    "bearer", "api_key", "apikey", "api-key",
    "password", "passwd", "pwd", "secret",
    "authorization", "auth", "credential",
    "oauth", "oauth_token", "id_token",
    "jwt", "x-auth", "x-token", "csrf", "xsrf"
];

function _isAuthKey(key) {
    if (!key) return false;
    var lower = key.toString().toLowerCase();
    for (var i = 0; i < AUTH_KEYS.length; i++) {
        if (lower.indexOf(AUTH_KEYS[i]) !== -1) return true;
    }
    return false;
}

function _truncate(val, maxLen) {
    if (!val) return "";
    var s = val.toString();
    if (s.length > (maxLen || 120)) return s.substring(0, maxLen || 120) + "...";
    return s;
}

function _send(op, storage, key, detail) {
    send({
        type: "auth_hook",
        operation: op,
        storage: storage || "",
        key: key || "",
        detail: detail || ""
    });
}

// ── Android ────────────────────────────────────────────────────────────

if (Java.available) {
    Java.perform(function () {

        // 1. SharedPreferences.getString — most common token store
        try {
            var SPImpl = Java.use("android.app.SharedPreferencesImpl");
            SPImpl.getString.implementation = function (key, defValue) {
                var result = this.getString(key, defValue);
                if (_isAuthKey(key)) {
                    _send("read", "SharedPreferences", key,
                        "value=" + _truncate(result, 80));
                }
                return result;
            };
        } catch (e) { /* skip */ }

        // 2. SharedPreferences.Editor.putString — writing tokens
        try {
            var SPEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
            SPEditor.putString.implementation = function (key, value) {
                if (_isAuthKey(key)) {
                    _send("write", "SharedPreferences", key,
                        "value=" + _truncate(value, 80));
                }
                return this.putString(key, value);
            };
        } catch (e) { /* skip */ }

        // 3. AccountManager.getAuthToken
        try {
            var AM = Java.use("android.accounts.AccountManager");
            AM.getAuthToken.overload("android.accounts.Account", "java.lang.String", "android.os.Bundle", "android.app.Activity", "android.accounts.AccountManagerCallback", "android.os.Handler").implementation = function (account, authTokenType, options, activity, callback, handler) {
                var acctName = account ? account.name.value : "unknown";
                _send("get_token", "AccountManager", authTokenType,
                    "account=" + acctName + " type=" + authTokenType);
                return this.getAuthToken(account, authTokenType, options, activity, callback, handler);
            };
        } catch (e) { /* skip */ }

        // 4. WebView.loadUrl — detect OAuth redirect flows
        try {
            var WebView = Java.use("android.webkit.WebView");
            WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
                var urlStr = url ? url.toString() : "";
                var lower = urlStr.toLowerCase();
                if (lower.indexOf("oauth") !== -1 || lower.indexOf("authorize") !== -1 ||
                    lower.indexOf("callback") !== -1 || lower.indexOf("redirect_uri") !== -1 ||
                    lower.indexOf("access_token") !== -1 || lower.indexOf("code=") !== -1) {
                    _send("oauth_flow", "WebView", "loadUrl",
                        "url=" + _truncate(urlStr, 200));
                }
                return this.loadUrl(url);
            };
        } catch (e) { /* skip */ }

        // 5. HttpURLConnection.setRequestProperty — auth headers
        try {
            var HUC = Java.use("java.net.HttpURLConnection");
            HUC.setRequestProperty.implementation = function (key, value) {
                if (_isAuthKey(key)) {
                    _send("header", "HttpURLConnection", key,
                        "value=" + _truncate(value, 80));
                }
                return this.setRequestProperty(key, value);
            };
        } catch (e) { /* skip */ }

        // 6. OkHttp Request.Builder.addHeader — auth headers
        try {
            var ReqBuilder = Java.use("okhttp3.Request$Builder");
            ReqBuilder.addHeader.implementation = function (name, value) {
                if (_isAuthKey(name)) {
                    _send("header", "OkHttp", name,
                        "value=" + _truncate(value, 80));
                }
                return this.addHeader(name, value);
            };
        } catch (e) { /* skip */ }

        // 7. CookieManager — track auth cookies
        try {
            var CookieMgr = Java.use("android.webkit.CookieManager");
            CookieMgr.setCookie.overload("java.lang.String", "java.lang.String").implementation = function (url, value) {
                if (value && _isAuthKey(value)) {
                    _send("cookie_set", "CookieManager", url,
                        "cookie=" + _truncate(value, 120));
                }
                return this.setCookie(url, value);
            };
        } catch (e) { /* skip */ }
    });
}

// ── iOS ────────────────────────────────────────────────────────────────

if (ObjC.available) {

    // 1. NSUserDefaults — objectForKey
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        Interceptor.attach(NSUserDefaults["- objectForKey:"].implementation, {
            onEnter: function (args) {
                this._key = ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                if (_isAuthKey(this._key) && retval && !retval.isNull()) {
                    var val = "";
                    try { val = ObjC.Object(retval).toString(); } catch (e) {}
                    _send("read", "NSUserDefaults", this._key,
                        "value=" + _truncate(val, 80));
                }
            }
        });
    } catch (e) { /* skip */ }

    // 2. NSUserDefaults — setObject:forKey:
    try {
        Interceptor.attach(ObjC.classes.NSUserDefaults["- setObject:forKey:"].implementation, {
            onEnter: function (args) {
                var key = ObjC.Object(args[3]).toString();
                if (_isAuthKey(key)) {
                    var val = "";
                    try { val = ObjC.Object(args[2]).toString(); } catch (e) {}
                    _send("write", "NSUserDefaults", key,
                        "value=" + _truncate(val, 80));
                }
            }
        });
    } catch (e) { /* skip */ }

    // 3. SecItemCopyMatching — keychain reads
    try {
        var secItemCopy = Module.findExportByName("Security", "SecItemCopyMatching");
        if (secItemCopy) {
            Interceptor.attach(secItemCopy, {
                onEnter: function (args) {
                    try {
                        var query = ObjC.Object(args[0]);
                        var account = "";
                        var service = "";
                        try { account = query.objectForKey_("acct").toString(); } catch (e) {}
                        try { service = query.objectForKey_("svce").toString(); } catch (e) {}
                        if (account || service) {
                            _send("keychain_read", "Keychain", account || service,
                                "SecItemCopyMatching account=" + account + " service=" + service);
                        }
                    } catch (e) { /* skip */ }
                }
            });
        }
    } catch (e) { /* skip */ }

    // 4. SecItemAdd — keychain writes
    try {
        var secItemAdd = Module.findExportByName("Security", "SecItemAdd");
        if (secItemAdd) {
            Interceptor.attach(secItemAdd, {
                onEnter: function (args) {
                    try {
                        var attrs = ObjC.Object(args[0]);
                        var account = "";
                        var service = "";
                        var accessible = "";
                        try { account = attrs.objectForKey_("acct").toString(); } catch (e) {}
                        try { service = attrs.objectForKey_("svce").toString(); } catch (e) {}
                        try { accessible = attrs.objectForKey_("pdmn").toString(); } catch (e) {}
                        _send("keychain_write", "Keychain", account || service,
                            "SecItemAdd account=" + account + " service=" + service +
                            " accessible=" + accessible);
                    } catch (e) { /* skip */ }
                }
            });
        }
    } catch (e) { /* skip */ }

    // 5. WKWebView loadRequest — OAuth flows
    try {
        var WKWebView = ObjC.classes.WKWebView;
        if (WKWebView && WKWebView["- loadRequest:"]) {
            Interceptor.attach(WKWebView["- loadRequest:"].implementation, {
                onEnter: function (args) {
                    try {
                        var request = ObjC.Object(args[2]);
                        var url = request.URL().absoluteString().toString();
                        var lower = url.toLowerCase();
                        if (lower.indexOf("oauth") !== -1 || lower.indexOf("authorize") !== -1 ||
                            lower.indexOf("callback") !== -1 || lower.indexOf("access_token") !== -1) {
                            _send("oauth_flow", "WKWebView", "loadRequest",
                                "url=" + _truncate(url, 200));
                        }
                    } catch (e) { /* skip */ }
                }
            });
        }
    } catch (e) { /* skip */ }

    // 6. NSHTTPCookieStorage — auth cookies
    try {
        var CookieStorage = ObjC.classes.NSHTTPCookieStorage;
        if (CookieStorage["- setCookie:"]) {
            Interceptor.attach(CookieStorage["- setCookie:"].implementation, {
                onEnter: function (args) {
                    try {
                        var cookie = ObjC.Object(args[2]);
                        var name = cookie.name().toString();
                        if (_isAuthKey(name)) {
                            var value = cookie.value().toString();
                            var domain = cookie.domain().toString();
                            _send("cookie_set", "NSHTTPCookieStorage", name,
                                "domain=" + domain + " value=" + _truncate(value, 60));
                        }
                    } catch (e) { /* skip */ }
                }
            });
        }
    } catch (e) { /* skip */ }

    // 7. NSMutableURLRequest — setValue:forHTTPHeaderField:
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        if (NSMutableURLRequest["- setValue:forHTTPHeaderField:"]) {
            Interceptor.attach(NSMutableURLRequest["- setValue:forHTTPHeaderField:"].implementation, {
                onEnter: function (args) {
                    try {
                        var field = ObjC.Object(args[3]).toString();
                        if (_isAuthKey(field)) {
                            var value = ObjC.Object(args[2]).toString();
                            _send("header", "NSURLRequest", field,
                                "value=" + _truncate(value, 80));
                        }
                    } catch (e) { /* skip */ }
                }
            });
        }
    } catch (e) { /* skip */ }
}

send({ type: "auth_hook", operation: "init", storage: "", key: "", detail: "Auth hooks installed" });
