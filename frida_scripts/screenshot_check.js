(function() {
    'use strict';

    var CATALOGUE_ID = 'QUILL-INS-006';

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

    // ── Android hooks ──

    if (Java && Java.available) {
        Java.perform(function() {
            emitLog('[screenshot_check] Attaching Android screenshot prevention hooks');

            var FLAG_SECURE = 0x00002000;

            // Window.setFlags — detect FLAG_SECURE
            try {
                var Window = Java.use('android.view.Window');
                Window.setFlags.implementation = function(flags, mask) {
                    try {
                        if ((flags & FLAG_SECURE) !== 0) {
                            emitLog('[screenshot_check] FLAG_SECURE set via Window.setFlags');
                            emitFinding(
                                'Screenshot Prevention Enabled (FLAG_SECURE)',
                                'INFO',
                                'The application sets FLAG_SECURE on its window, preventing ' +
                                'screenshots and screen recording. This is a positive security control.',
                                {
                                    platform: 'android',
                                    mechanism: 'FLAG_SECURE',
                                    method: 'Window.setFlags',
                                    flags_hex: '0x' + flags.toString(16),
                                    protection_active: true
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[screenshot_check] Error in setFlags hook: ' + e);
                    }
                    return this.setFlags(flags, mask);
                };
            } catch (e) {
                emitLog('[screenshot_check] Failed to hook Window.setFlags: ' + e);
            }

            // Window.addFlags — alternative FLAG_SECURE set
            try {
                var Window2 = Java.use('android.view.Window');
                Window2.addFlags.implementation = function(flags) {
                    try {
                        if ((flags & FLAG_SECURE) !== 0) {
                            emitLog('[screenshot_check] FLAG_SECURE set via Window.addFlags');
                            emitFinding(
                                'Screenshot Prevention Enabled (FLAG_SECURE)',
                                'INFO',
                                'The application adds FLAG_SECURE to its window flags, preventing ' +
                                'screenshots and screen recording on this activity.',
                                {
                                    platform: 'android',
                                    mechanism: 'FLAG_SECURE',
                                    method: 'Window.addFlags',
                                    flags_hex: '0x' + flags.toString(16),
                                    protection_active: true
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[screenshot_check] Error in addFlags hook: ' + e);
                    }
                    return this.addFlags(flags);
                };
            } catch (e) {
                emitLog('[screenshot_check] Failed to hook Window.addFlags: ' + e);
            }

            // Window.clearFlags — detect FLAG_SECURE removal
            try {
                var Window3 = Java.use('android.view.Window');
                Window3.clearFlags.implementation = function(flags) {
                    try {
                        if ((flags & FLAG_SECURE) !== 0) {
                            emitLog('[screenshot_check] FLAG_SECURE cleared via Window.clearFlags');
                            emitFinding(
                                'Screenshot Prevention Removed',
                                'MEDIUM',
                                'The application clears FLAG_SECURE, re-enabling screenshots and screen recording. ' +
                                'If this occurs on sensitive screens it may expose confidential information.',
                                {
                                    platform: 'android',
                                    mechanism: 'FLAG_SECURE cleared',
                                    method: 'Window.clearFlags',
                                    flags_hex: '0x' + flags.toString(16),
                                    protection_active: false
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[screenshot_check] Error in clearFlags hook: ' + e);
                    }
                    return this.clearFlags(flags);
                };
            } catch (e) {
                emitLog('[screenshot_check] Failed to hook Window.clearFlags: ' + e);
            }

            // SurfaceView.setSecure — can bypass FLAG_SECURE on some devices
            try {
                var SurfaceView = Java.use('android.view.SurfaceView');
                SurfaceView.setSecure.implementation = function(isSecure) {
                    try {
                        emitLog('[screenshot_check] SurfaceView.setSecure(' + isSecure + ')');
                        emitFinding(
                            'SurfaceView Secure Flag ' + (isSecure ? 'Set' : 'Cleared'),
                            'INFO',
                            'SurfaceView.setSecure called with value ' + isSecure + '. ' +
                            (isSecure ? 'Surface content is protected from capture.' :
                             'Surface content is not protected from capture.'),
                            {
                                platform: 'android',
                                mechanism: 'SurfaceView.setSecure',
                                is_secure: isSecure,
                                protection_active: isSecure
                            }
                        );
                    } catch (e) {
                        emitLog('[screenshot_check] Error in SurfaceView.setSecure hook: ' + e);
                    }
                    return this.setSecure(isSecure);
                };
            } catch (e) {
                emitLog('[screenshot_check] Failed to hook SurfaceView.setSecure: ' + e);
            }

            // Activity.onResume — check current FLAG_SECURE state per screen
            try {
                var Activity = Java.use('android.app.Activity');
                Activity.onResume.implementation = function() {
                    this.onResume();
                    try {
                        var window = this.getWindow();
                        if (window !== null) {
                            var attrs = window.getAttributes();
                            var currentFlags = attrs.flags.value;
                            var hasSecure = (currentFlags & FLAG_SECURE) !== 0;
                            var activityName = this.getClass().getName();
                            emitLog('[screenshot_check] Activity resumed: ' + activityName +
                                    ' | FLAG_SECURE: ' + hasSecure);
                            if (!hasSecure) {
                                emitFinding(
                                    'Screen Not Protected from Screenshots',
                                    'INFO',
                                    'Activity ' + activityName + ' does not set FLAG_SECURE. ' +
                                    'Screenshots and screen recording are permitted.',
                                    {
                                        platform: 'android',
                                        activity: activityName,
                                        flag_secure: false,
                                        protection_active: false
                                    }
                                );
                            }
                        }
                    } catch (e) {
                        emitLog('[screenshot_check] Error checking activity flags: ' + e);
                    }
                };
            } catch (e) {
                emitLog('[screenshot_check] Failed to hook Activity.onResume: ' + e);
            }

            // EditText.setInputType — detect password fields for context
            try {
                var EditText = Java.use('android.widget.EditText');
                EditText.setInputType.implementation = function(type) {
                    try {
                        var isPassword = (type & 0x80) !== 0 || (type & 0x10) !== 0;
                        if (isPassword) {
                            emitLog('[screenshot_check] Password input field detected (type=0x' +
                                    type.toString(16) + ')');
                        }
                    } catch (e) { /* ignore */ }
                    return this.setInputType(type);
                };
            } catch (e) {
                emitLog('[screenshot_check] Failed to hook EditText.setInputType: ' + e);
            }

            emitLog('[screenshot_check] Android screenshot hooks attached');
        });
    }

    // ── iOS hooks ──

    if (ObjC && ObjC.available) {
        emitLog('[screenshot_check] Attaching iOS screenshot prevention hooks');

        // UIScreen.isCaptured
        try {
            var UIScreen = ObjC.classes.UIScreen;
            if (UIScreen['- isCaptured']) {
                Interceptor.attach(UIScreen['- isCaptured'].implementation, {
                    onLeave: function(retval) {
                        try {
                            var captured = retval.toInt32() !== 0;
                            if (captured) {
                                emitLog('[screenshot_check] UIScreen.isCaptured=YES (recording active)');
                                emitFinding(
                                    'Screen Recording Detection Active',
                                    'INFO',
                                    'The application checks UIScreen.isCaptured, indicating awareness ' +
                                    'of screen recording. This is a positive security control.',
                                    {
                                        platform: 'ios',
                                        mechanism: 'UIScreen.isCaptured',
                                        is_captured: true,
                                        protection_active: true
                                    }
                                );
                            }
                        } catch (e) {
                            emitLog('[screenshot_check] Error in isCaptured hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[screenshot_check] Failed to hook UIScreen.isCaptured: ' + e);
        }

        // NSNotificationCenter — screenshot and capture notification registration
        try {
            var NSNotificationCenter = ObjC.classes.NSNotificationCenter;
            Interceptor.attach(NSNotificationCenter['- addObserver:selector:name:object:'].implementation, {
                onEnter: function(args) {
                    try {
                        var name = ObjC.Object(args[4]).toString();
                        if (name.indexOf('UIApplicationUserDidTakeScreenshotNotification') !== -1) {
                            var observer = ObjC.Object(args[2]).$className;
                            emitLog('[screenshot_check] Screenshot notification registered by: ' + observer);
                            emitFinding(
                                'Screenshot Detection Notification Registered',
                                'INFO',
                                'The application registers for UIApplicationUserDidTakeScreenshotNotification. ' +
                                'It will be notified when a screenshot is taken but cannot prevent it.',
                                {
                                    platform: 'ios',
                                    mechanism: 'UIApplicationUserDidTakeScreenshotNotification',
                                    observer_class: observer,
                                    prevents_screenshot: false,
                                    detects_screenshot: true
                                }
                            );
                        }
                        if (name.indexOf('UIScreenCapturedDidChangeNotification') !== -1) {
                            var observer2 = ObjC.Object(args[2]).$className;
                            emitLog('[screenshot_check] Screen capture change notification registered by: ' + observer2);
                            emitFinding(
                                'Screen Recording Detection Registered',
                                'INFO',
                                'The application registers for UIScreenCapturedDidChangeNotification, ' +
                                'enabling detection of screen recording state changes.',
                                {
                                    platform: 'ios',
                                    mechanism: 'UIScreenCapturedDidChangeNotification',
                                    observer_class: observer2,
                                    protection_active: true
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[screenshot_check] Error in notification hook: ' + e);
                    }
                }
            });
        } catch (e) {
            emitLog('[screenshot_check] Failed to hook NSNotificationCenter: ' + e);
        }

        // UITextField.setSecureTextEntry — secure field detection
        try {
            Interceptor.attach(ObjC.classes.UITextField['- setSecureTextEntry:'].implementation, {
                onEnter: function(args) {
                    try {
                        var secure = args[2].toInt32() !== 0;
                        emitLog('[screenshot_check] UITextField.setSecureTextEntry: ' + secure);
                    } catch (e) { /* ignore */ }
                }
            });
        } catch (e) {
            emitLog('[screenshot_check] Failed to hook UITextField secure entry: ' + e);
        }

        // CALayer.setAllowsScreenRecording (iOS 16+)
        try {
            var CALayer = ObjC.classes.CALayer;
            if (CALayer['- setAllowsScreenRecording:']) {
                Interceptor.attach(CALayer['- setAllowsScreenRecording:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var allowed = args[2].toInt32() !== 0;
                            emitLog('[screenshot_check] CALayer.setAllowsScreenRecording: ' + allowed);
                            emitFinding(
                                'Layer Screen Recording ' + (allowed ? 'Allowed' : 'Blocked'),
                                'INFO',
                                'CALayer.setAllowsScreenRecording set to ' + allowed + '.',
                                {
                                    platform: 'ios',
                                    mechanism: 'CALayer.setAllowsScreenRecording',
                                    allowed: allowed,
                                    protection_active: !allowed
                                }
                            );
                        } catch (e) {
                            emitLog('[screenshot_check] Error in CALayer hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[screenshot_check] Failed to hook CALayer.setAllowsScreenRecording: ' + e);
        }

        emitLog('[screenshot_check] iOS screenshot hooks attached');
    }
})();
