(function() {
    'use strict';

    var CATALOGUE_ID = 'QUILL-INS-005';
    var MAX_CONTENT_LEN = 200;

    var SENSITIVE_PATTERNS = [
        { name: 'JWT', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
        { name: 'password parameter', regex: /password\s*[=:]\s*\S+/i },
        { name: 'token parameter', regex: /token\s*[=:]\s*\S+/i },
        { name: 'Bearer token', regex: /[Bb]earer\s+[A-Za-z0-9_\-\.]+/i },
        { name: 'credit card (Visa)', regex: /\b4[0-9]{12}(?:[0-9]{3})?\b/ },
        { name: 'credit card (MC)', regex: /\b5[1-5][0-9]{14}\b/ },
        { name: 'credit card (Amex)', regex: /\b3[47][0-9]{13}\b/ },
        { name: 'API key parameter', regex: /api[_-]?key\s*[=:]\s*\S+/i },
        { name: 'secret parameter', regex: /secret\s*[=:]\s*\S+/i }
    ];

    function truncate(str) {
        if (!str) return '';
        var s = String(str);
        return s.length > MAX_CONTENT_LEN ? s.substring(0, MAX_CONTENT_LEN) + '...[truncated]' : s;
    }

    function checkSensitive(content) {
        if (!content) return [];
        var hits = [];
        var s = String(content);
        for (var i = 0; i < SENSITIVE_PATTERNS.length; i++) {
            if (SENSITIVE_PATTERNS[i].regex.test(s)) {
                hits.push(SENSITIVE_PATTERNS[i].name);
            }
        }
        return hits;
    }

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

    function getCallerInfo() {
        try {
            var stack = Java.use('java.lang.Thread').currentThread().getStackTrace();
            for (var i = 0; i < stack.length && i < 15; i++) {
                var cls = stack[i].getClassName();
                if (cls.indexOf('android.content.ClipboardManager') === -1 &&
                    cls.indexOf('java.lang.reflect') === -1 &&
                    cls.indexOf('java.lang.Thread') === -1 &&
                    cls.indexOf('com.android.internal') === -1) {
                    return cls + '.' + stack[i].getMethodName();
                }
            }
        } catch (e) { /* ignore */ }
        return 'unknown';
    }

    // ── Android hooks ──

    if (Java && Java.available) {
        Java.perform(function() {
            emitLog('[clipboard_monitor] Attaching Android clipboard hooks');

            // setPrimaryClip (clipboard write)
            try {
                var ClipboardManager = Java.use('android.content.ClipboardManager');
                ClipboardManager.setPrimaryClip.implementation = function(clip) {
                    try {
                        var itemCount = clip.getItemCount();
                        var content = '';
                        for (var i = 0; i < itemCount; i++) {
                            var item = clip.getItemAt(i);
                            var text = item.getText();
                            if (text !== null) content += String(text);
                        }
                        var caller = getCallerInfo();
                        var truncated = truncate(content);
                        emitLog('[clipboard_monitor] setPrimaryClip by ' + caller + ' | content: ' + truncated);
                        var sensitive = checkSensitive(content);
                        if (sensitive.length > 0) {
                            emitFinding(
                                'Sensitive Data Written to Clipboard',
                                'HIGH',
                                'The application wrote potentially sensitive data to the system clipboard. ' +
                                'Clipboard contents are accessible to any app on the device.',
                                {
                                    operation: 'write',
                                    platform: 'android',
                                    caller: caller,
                                    content_preview: truncated,
                                    sensitive_patterns: sensitive
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[clipboard_monitor] Error in setPrimaryClip hook: ' + e);
                    }
                    return this.setPrimaryClip(clip);
                };
            } catch (e) {
                emitLog('[clipboard_monitor] Failed to hook setPrimaryClip: ' + e);
            }

            // getPrimaryClip (clipboard read)
            try {
                var ClipboardManager2 = Java.use('android.content.ClipboardManager');
                ClipboardManager2.getPrimaryClip.implementation = function() {
                    var result = this.getPrimaryClip();
                    try {
                        var content = '';
                        if (result !== null && result.getItemCount() > 0) {
                            for (var i = 0; i < result.getItemCount(); i++) {
                                var item = result.getItemAt(i);
                                var text = item.getText();
                                if (text !== null) content += String(text);
                            }
                        }
                        var caller = getCallerInfo();
                        var truncated = truncate(content);
                        emitLog('[clipboard_monitor] getPrimaryClip by ' + caller + ' | content: ' + truncated);
                        var sensitive = checkSensitive(content);
                        if (sensitive.length > 0) {
                            emitFinding(
                                'Sensitive Data Read from Clipboard',
                                'MEDIUM',
                                'The application read clipboard contents that contain potentially sensitive data.',
                                {
                                    operation: 'read',
                                    platform: 'android',
                                    caller: caller,
                                    content_preview: truncated,
                                    sensitive_patterns: sensitive
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[clipboard_monitor] Error in getPrimaryClip hook: ' + e);
                    }
                    return result;
                };
            } catch (e) {
                emitLog('[clipboard_monitor] Failed to hook getPrimaryClip: ' + e);
            }

            // getText (deprecated but still used)
            try {
                var ClipboardManager3 = Java.use('android.content.ClipboardManager');
                ClipboardManager3.getText.implementation = function() {
                    var text = this.getText();
                    try {
                        var str = text ? text.toString() : '';
                        var caller = getCallerInfo();
                        var truncated = truncate(str);
                        emitLog('[clipboard_monitor] getText (deprecated) by ' + caller + ' | content: ' + truncated);
                        var sensitive = checkSensitive(str);
                        if (sensitive.length > 0) {
                            emitFinding(
                                'Sensitive Data Read from Clipboard (Deprecated API)',
                                'MEDIUM',
                                'The application read clipboard via deprecated getText(). Content contains sensitive data.',
                                {
                                    operation: 'read',
                                    platform: 'android',
                                    caller: caller,
                                    content_preview: truncated,
                                    sensitive_patterns: sensitive,
                                    api: 'getText (deprecated)'
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[clipboard_monitor] Error in getText hook: ' + e);
                    }
                    return text;
                };
            } catch (e) {
                emitLog('[clipboard_monitor] Failed to hook getText: ' + e);
            }

            // ClipData.newPlainText — track clip creation with sensitive data
            try {
                var ClipData = Java.use('android.content.ClipData');
                ClipData.newPlainText.implementation = function(label, text) {
                    try {
                        var str = text ? text.toString() : '';
                        var sensitive = checkSensitive(str);
                        if (sensitive.length > 0) {
                            var truncated = truncate(str);
                            emitLog('[clipboard_monitor] ClipData.newPlainText with sensitive data | label: ' + label);
                            emitFinding(
                                'Sensitive Data in ClipData Creation',
                                'MEDIUM',
                                'A ClipData object was created with sensitive content before being placed on clipboard.',
                                {
                                    operation: 'clip_create',
                                    platform: 'android',
                                    label: label ? String(label) : '',
                                    content_preview: truncated,
                                    sensitive_patterns: sensitive
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[clipboard_monitor] Error in newPlainText hook: ' + e);
                    }
                    return this.newPlainText(label, text);
                };
            } catch (e) {
                emitLog('[clipboard_monitor] Failed to hook ClipData.newPlainText: ' + e);
            }

            emitLog('[clipboard_monitor] Android clipboard hooks attached');
        });
    }

    // ── iOS hooks ──

    if (ObjC && ObjC.available) {
        emitLog('[clipboard_monitor] Attaching iOS clipboard hooks');

        // UIPasteboard setString: (clipboard write)
        try {
            var UIPasteboard = ObjC.classes.UIPasteboard;
            Interceptor.attach(UIPasteboard['- setString:'].implementation, {
                onEnter: function(args) {
                    try {
                        var content = ObjC.Object(args[2]).toString();
                        var truncated = truncate(content);
                        emitLog('[clipboard_monitor] UIPasteboard setString: | content: ' + truncated);
                        var sensitive = checkSensitive(content);
                        if (sensitive.length > 0) {
                            emitFinding(
                                'Sensitive Data Written to Clipboard',
                                'HIGH',
                                'The application wrote potentially sensitive data to UIPasteboard. ' +
                                'Pasteboard contents are accessible to other apps.',
                                {
                                    operation: 'write',
                                    platform: 'ios',
                                    content_preview: truncated,
                                    sensitive_patterns: sensitive
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[clipboard_monitor] Error in setString: hook: ' + e);
                    }
                }
            });
        } catch (e) {
            emitLog('[clipboard_monitor] Failed to hook UIPasteboard setString: ' + e);
        }

        // UIPasteboard string (getter — clipboard read)
        try {
            var UIPasteboard2 = ObjC.classes.UIPasteboard;
            Interceptor.attach(UIPasteboard2['- string'].implementation, {
                onLeave: function(retval) {
                    try {
                        if (retval.isNull()) return;
                        var content = ObjC.Object(retval).toString();
                        var truncated = truncate(content);
                        emitLog('[clipboard_monitor] UIPasteboard string read | content: ' + truncated);
                        var sensitive = checkSensitive(content);
                        if (sensitive.length > 0) {
                            emitFinding(
                                'Sensitive Data Read from Clipboard',
                                'MEDIUM',
                                'The application read pasteboard contents containing potentially sensitive data.',
                                {
                                    operation: 'read',
                                    platform: 'ios',
                                    content_preview: truncated,
                                    sensitive_patterns: sensitive
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[clipboard_monitor] Error in string getter hook: ' + e);
                    }
                }
            });
        } catch (e) {
            emitLog('[clipboard_monitor] Failed to hook UIPasteboard string getter: ' + e);
        }

        // generalPasteboard access
        try {
            Interceptor.attach(ObjC.classes.UIPasteboard['+ generalPasteboard'].implementation, {
                onLeave: function() {
                    emitLog('[clipboard_monitor] UIPasteboard generalPasteboard accessed');
                }
            });
        } catch (e) {
            emitLog('[clipboard_monitor] Failed to hook generalPasteboard: ' + e);
        }

        // setItems:options: (bulk clipboard set)
        try {
            var UIPasteboard3 = ObjC.classes.UIPasteboard;
            if (UIPasteboard3['- setItems:options:']) {
                Interceptor.attach(UIPasteboard3['- setItems:options:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var items = ObjC.Object(args[2]);
                            emitLog('[clipboard_monitor] UIPasteboard setItems:options: count=' + items.count());
                        } catch (e) {
                            emitLog('[clipboard_monitor] Error in setItems hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[clipboard_monitor] Failed to hook setItems:options: ' + e);
        }

        // setValue:forPasteboardType: (typed clipboard set)
        try {
            var UIPasteboard4 = ObjC.classes.UIPasteboard;
            if (UIPasteboard4['- setValue:forPasteboardType:']) {
                Interceptor.attach(UIPasteboard4['- setValue:forPasteboardType:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var val = ObjC.Object(args[2]).toString();
                            var pbType = ObjC.Object(args[3]).toString();
                            var truncated = truncate(val);
                            var sensitive = checkSensitive(val);
                            if (sensitive.length > 0) {
                                emitFinding(
                                    'Sensitive Data Written to Clipboard (Typed)',
                                    'HIGH',
                                    'Sensitive data written via setValue:forPasteboardType: with type ' + pbType,
                                    {
                                        operation: 'write_typed',
                                        platform: 'ios',
                                        pasteboard_type: pbType,
                                        content_preview: truncated,
                                        sensitive_patterns: sensitive
                                    }
                                );
                            }
                        } catch (e) {
                            emitLog('[clipboard_monitor] Error in setValue:forPasteboardType: hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[clipboard_monitor] Failed to hook setValue:forPasteboardType: ' + e);
        }

        emitLog('[clipboard_monitor] iOS clipboard hooks attached');
    }
})();
