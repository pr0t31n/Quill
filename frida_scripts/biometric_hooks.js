(function() {
    'use strict';

    var CATALOGUE_ID = 'QUILL-INS-009';

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
                if (cls.indexOf('android.hardware') === -1 &&
                    cls.indexOf('androidx.biometric') === -1 &&
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
            emitLog('[biometric_hooks] Attaching Android biometric hooks');

            // AndroidX BiometricPrompt.authenticate(PromptInfo, CryptoObject) — strong
            try {
                var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
                BiometricPrompt.authenticate.overload(
                    'androidx.biometric.BiometricPrompt$PromptInfo',
                    'androidx.biometric.BiometricPrompt$CryptoObject'
                ).implementation = function(promptInfo, cryptoObject) {
                    try {
                        var caller = getCallerClass();
                        var title = promptInfo.getTitle() ? String(promptInfo.getTitle()) : 'unknown';
                        emitLog('[biometric_hooks] BiometricPrompt.authenticate (with CryptoObject) | ' +
                                'title: ' + title + ' | caller: ' + caller);
                        emitFinding(
                            'Biometric Authentication with CryptoObject (Strong)',
                            'INFO',
                            'BiometricPrompt.authenticate with a CryptoObject binds biometric auth ' +
                            'to a cryptographic operation. This is the strong, recommended implementation.',
                            {
                                platform: 'android', component: 'BiometricPrompt',
                                method: 'authenticate(PromptInfo, CryptoObject)',
                                prompt_title: title, has_crypto_object: true,
                                auth_strength: 'strong', caller: caller
                            }
                        );
                    } catch (e) {
                        emitLog('[biometric_hooks] Error in authenticate(crypto) hook: ' + e);
                    }
                    return this.authenticate(promptInfo, cryptoObject);
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook BiometricPrompt.authenticate(PI, CO): ' + e);
            }

            // AndroidX BiometricPrompt.authenticate(PromptInfo) — callback only (weak)
            try {
                var BiometricPrompt2 = Java.use('androidx.biometric.BiometricPrompt');
                BiometricPrompt2.authenticate.overload(
                    'androidx.biometric.BiometricPrompt$PromptInfo'
                ).implementation = function(promptInfo) {
                    try {
                        var caller = getCallerClass();
                        var title = promptInfo.getTitle() ? String(promptInfo.getTitle()) : 'unknown';
                        var allowedAuth = 0;
                        try { allowedAuth = promptInfo.getAllowedAuthenticators(); } catch (e) {}
                        var authTypes = [];
                        if (allowedAuth & 0x000F) authTypes.push('BIOMETRIC_STRONG');
                        if ((allowedAuth & 0x00FF) && !(allowedAuth & 0x000F)) authTypes.push('BIOMETRIC_WEAK');
                        if (allowedAuth & 0x8000) authTypes.push('DEVICE_CREDENTIAL');

                        emitLog('[biometric_hooks] BiometricPrompt.authenticate (NO CryptoObject) | ' +
                                'title: ' + title + ' | auth: ' + authTypes.join('+') + ' | caller: ' + caller);

                        emitFinding(
                            'Biometric Authentication Without CryptoObject (Weak/Bypassable)',
                            'HIGH',
                            'BiometricPrompt.authenticate without CryptoObject. Authentication is ' +
                            'callback-based only and can be bypassed by hooking onAuthenticationSucceeded. ' +
                            'The app should bind authentication to a cryptographic operation.',
                            {
                                platform: 'android', component: 'BiometricPrompt',
                                method: 'authenticate(PromptInfo)', prompt_title: title,
                                has_crypto_object: false, auth_strength: 'weak',
                                bypassable: true, caller: caller,
                                allowed_authenticators: authTypes.join('+')
                            }
                        );

                        if (authTypes.indexOf('DEVICE_CREDENTIAL') !== -1) {
                            emitFinding(
                                'Biometric Allows Device Credential Fallback',
                                'MEDIUM',
                                'BiometricPrompt allows fallback to device passcode/PIN, which is ' +
                                'weaker than biometric-only authentication.',
                                {
                                    platform: 'android', component: 'BiometricPrompt',
                                    prompt_title: title, has_credential_fallback: true,
                                    allowed_authenticators: authTypes.join('+')
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[biometric_hooks] Error in authenticate(callback) hook: ' + e);
                    }
                    return this.authenticate(promptInfo);
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook BiometricPrompt.authenticate(PI): ' + e);
            }

            // Deprecated FingerprintManager.authenticate
            try {
                var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
                FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
                    try {
                        var hasCrypto = crypto !== null;
                        var caller = getCallerClass();
                        emitLog('[biometric_hooks] FingerprintManager.authenticate | ' +
                                'hasCryptoObject: ' + hasCrypto + ' | caller: ' + caller);

                        emitFinding(
                            'Deprecated FingerprintManager Used for Biometric Auth',
                            'MEDIUM',
                            'The application uses deprecated FingerprintManager instead of BiometricPrompt. ' +
                            'FingerprintManager lacks device credential fallback and strongbox support.',
                            {
                                platform: 'android', component: 'FingerprintManager',
                                method: 'authenticate', has_crypto_object: hasCrypto,
                                deprecated: true, caller: caller
                            }
                        );

                        if (!hasCrypto) {
                            emitFinding(
                                'FingerprintManager Auth Without CryptoObject (Weak/Bypassable)',
                                'HIGH',
                                'Deprecated FingerprintManager.authenticate without CryptoObject. ' +
                                'Purely callback-based and trivially bypassable through instrumentation.',
                                {
                                    platform: 'android', component: 'FingerprintManager',
                                    method: 'authenticate', has_crypto_object: false,
                                    auth_strength: 'weak', bypassable: true, caller: caller
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[biometric_hooks] Error in FingerprintManager.authenticate hook: ' + e);
                    }
                    return this.authenticate(crypto, cancel, flags, callback, handler);
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook FingerprintManager.authenticate: ' + e);
            }

            // Platform BiometricPrompt (non-AndroidX, API 28+) — without CryptoObject
            try {
                var PlatformBP = Java.use('android.hardware.biometrics.BiometricPrompt');
                PlatformBP.authenticate.overload(
                    'android.os.CancellationSignal', 'java.util.concurrent.Executor',
                    'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
                ).implementation = function(cancel, executor, callback) {
                    emitLog('[biometric_hooks] Platform BiometricPrompt.authenticate (no CryptoObject)');
                    emitFinding(
                        'Biometric Authentication Without CryptoObject (Weak/Bypassable)',
                        'HIGH',
                        'Platform BiometricPrompt.authenticate without CryptoObject is callback-based ' +
                        'and bypassable.',
                        {
                            platform: 'android', component: 'android.hardware.biometrics.BiometricPrompt',
                            method: 'authenticate(CancelSignal, Executor, Callback)',
                            has_crypto_object: false, auth_strength: 'weak', bypassable: true
                        }
                    );
                    return this.authenticate(cancel, executor, callback);
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook platform BiometricPrompt (no crypto): ' + e);
            }

            // Platform BiometricPrompt — with CryptoObject
            try {
                var PlatformBP2 = Java.use('android.hardware.biometrics.BiometricPrompt');
                PlatformBP2.authenticate.overload(
                    'android.hardware.biometrics.BiometricPrompt$CryptoObject',
                    'android.os.CancellationSignal', 'java.util.concurrent.Executor',
                    'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
                ).implementation = function(crypto, cancel, executor, callback) {
                    emitLog('[biometric_hooks] Platform BiometricPrompt.authenticate WITH CryptoObject');
                    emitFinding(
                        'Biometric Authentication with CryptoObject (Strong)',
                        'INFO',
                        'Platform BiometricPrompt.authenticate with CryptoObject provides key-bound biometric auth.',
                        {
                            platform: 'android', component: 'android.hardware.biometrics.BiometricPrompt',
                            method: 'authenticate(CryptoObject, CancelSignal, Executor, Callback)',
                            has_crypto_object: true, auth_strength: 'strong'
                        }
                    );
                    return this.authenticate(crypto, cancel, executor, callback);
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook platform BiometricPrompt (crypto): ' + e);
            }

            // AuthenticationCallback.onAuthenticationSucceeded — check CryptoObject in result
            try {
                var AuthCallback = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
                AuthCallback.onAuthenticationSucceeded.implementation = function(result) {
                    try {
                        var cryptoObj = result.getCryptoObject();
                        var hasCrypto = cryptoObj !== null;
                        var cryptoType = 'none';
                        if (hasCrypto) {
                            try { if (cryptoObj.getCipher() !== null) cryptoType = 'Cipher'; } catch (e) {}
                            try { if (cryptoObj.getSignature() !== null) cryptoType = 'Signature'; } catch (e) {}
                            try { if (cryptoObj.getMac() !== null) cryptoType = 'Mac'; } catch (e) {}
                        }
                        emitLog('[biometric_hooks] onAuthenticationSucceeded | hasCrypto: ' + hasCrypto +
                                ' | type: ' + cryptoType);
                        if (!hasCrypto) {
                            emitFinding(
                                'Biometric Success Without Crypto Binding',
                                'HIGH',
                                'Biometric authentication succeeded but the result contains no CryptoObject. ' +
                                'The outcome is a simple boolean callback that can be replayed or faked.',
                                {
                                    platform: 'android', component: 'BiometricPrompt.AuthenticationCallback',
                                    method: 'onAuthenticationSucceeded', has_crypto_object: false,
                                    crypto_type: 'none', bypassable: true
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[biometric_hooks] Error in onAuthenticationSucceeded hook: ' + e);
                    }
                    return this.onAuthenticationSucceeded(result);
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook onAuthenticationSucceeded: ' + e);
            }

            // BiometricManager.canAuthenticate — capability check
            try {
                var BiometricManager = Java.use('androidx.biometric.BiometricManager');
                BiometricManager.canAuthenticate.overload('int').implementation = function(authenticators) {
                    var result = this.canAuthenticate(authenticators);
                    try {
                        var authTypes = [];
                        if ((authenticators & 0x000F) !== 0) authTypes.push('BIOMETRIC_STRONG');
                        if ((authenticators & 0x00FF) !== 0 && (authenticators & 0x000F) === 0) authTypes.push('BIOMETRIC_WEAK');
                        if ((authenticators & 0x8000) !== 0) authTypes.push('DEVICE_CREDENTIAL');
                        var resultNames = {
                            0: 'SUCCESS', 1: 'STATUS_UNKNOWN', 11: 'ERROR_NO_HARDWARE',
                            12: 'ERROR_HW_UNAVAILABLE', 15: 'ERROR_NONE_ENROLLED',
                            14: 'ERROR_SECURITY_UPDATE_REQUIRED'
                        };
                        var resultStr = resultNames[result] || String(result);
                        emitLog('[biometric_hooks] canAuthenticate | auth: ' +
                                authTypes.join('|') + ' | result: ' + resultStr);
                    } catch (e) {
                        emitLog('[biometric_hooks] Error in canAuthenticate hook: ' + e);
                    }
                    return result;
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook BiometricManager.canAuthenticate: ' + e);
            }

            // KeyguardManager.isDeviceSecure
            try {
                var KGM = Java.use('android.app.KeyguardManager');
                KGM.isDeviceSecure.implementation = function() {
                    var result = this.isDeviceSecure();
                    emitLog('[biometric_hooks] KeyguardManager.isDeviceSecure: ' + result);
                    return result;
                };
            } catch (e) {
                emitLog('[biometric_hooks] Failed to hook KeyguardManager.isDeviceSecure: ' + e);
            }

            emitLog('[biometric_hooks] Android biometric hooks attached');
        });
    }

    // ── iOS hooks ──

    if (ObjC && ObjC.available) {
        emitLog('[biometric_hooks] Attaching iOS biometric hooks');

        var LA_POLICIES = {
            1: 'DeviceOwnerAuthenticationWithBiometrics',
            2: 'DeviceOwnerAuthentication',
            3: 'DeviceOwnerAuthenticationWithWatch',
            4: 'DeviceOwnerAuthenticationWithBiometricsOrWatch'
        };

        var LA_ERRORS = {
            '-1': 'AuthenticationFailed', '-2': 'UserCancel', '-3': 'UserFallback',
            '-4': 'SystemCancel', '-5': 'PasscodeNotSet', '-6': 'BiometryNotAvailable',
            '-7': 'BiometryNotEnrolled', '-8': 'BiometryLockout', '-9': 'AppCancel',
            '-10': 'InvalidContext', '-11': 'WatchNotAvailable'
        };

        // LAContext.evaluatePolicy:localizedReason:reply:
        try {
            var LAContext = ObjC.classes.LAContext;
            if (LAContext) {
                Interceptor.attach(LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var policy = args[2].toInt32();
                            var reason = ObjC.Object(args[3]).toString();
                            var policyName = LA_POLICIES[policy] || ('policy_' + policy);

                            emitLog('[biometric_hooks] LAContext.evaluatePolicy | policy: ' +
                                    policyName + ' | reason: ' + reason);

                            emitFinding(
                                'iOS Biometric Auth Is Callback-Based (Bypassable)',
                                'HIGH',
                                'LAContext.evaluatePolicy (' + policyName + ') is callback-based. ' +
                                'The reply block receives a boolean that can be hooked and forced to YES. ' +
                                'For strong security, bind biometric auth to Keychain access via ' +
                                'SecAccessControl with kSecAccessControlBiometryAny.',
                                {
                                    platform: 'ios', component: 'LAContext',
                                    method: 'evaluatePolicy:localizedReason:reply:',
                                    policy: policyName, policy_value: policy, reason: reason,
                                    bypassable: true, auth_strength: 'callback-based'
                                }
                            );

                            if (policy === 2) {
                                emitFinding(
                                    'Biometric Allows Passcode Fallback',
                                    'INFO',
                                    'LAPolicy.deviceOwnerAuthentication allows passcode fallback.',
                                    {
                                        platform: 'ios', component: 'LAContext',
                                        policy: policyName, has_passcode_fallback: true
                                    }
                                );
                            }

                            // Wrap reply block to monitor outcome
                            try {
                                var origBlock = new ObjC.Block(args[4]);
                                var origImpl = origBlock.implementation;
                                origBlock.implementation = function(success, error) {
                                    if (success) {
                                        emitLog('[biometric_hooks] evaluatePolicy reply: success=YES');
                                    } else {
                                        var errCode = '';
                                        var errDesc = '';
                                        if (error) {
                                            try {
                                                var nsErr = ObjC.Object(error);
                                                errCode = nsErr.code();
                                                errDesc = nsErr.localizedDescription().toString();
                                            } catch (e) {}
                                        }
                                        var errName = LA_ERRORS[String(errCode)] || '';
                                        emitLog('[biometric_hooks] evaluatePolicy reply: failed code=' +
                                                errCode + ' (' + errName + ') ' + errDesc);
                                    }
                                    origImpl(success, error);
                                };
                            } catch (e) {
                                emitLog('[biometric_hooks] Could not wrap reply block: ' + e);
                            }
                        } catch (e) {
                            emitLog('[biometric_hooks] Error in evaluatePolicy hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[biometric_hooks] Failed to hook LAContext.evaluatePolicy: ' + e);
        }

        // LAContext.canEvaluatePolicy:error:
        try {
            var LAContext2 = ObjC.classes.LAContext;
            if (LAContext2) {
                Interceptor.attach(LAContext2['- canEvaluatePolicy:error:'].implementation, {
                    onEnter: function(args) {
                        this._policy = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        try {
                            var canEval = retval.toInt32() !== 0;
                            var policyName = LA_POLICIES[this._policy] || ('policy_' + this._policy);
                            emitLog('[biometric_hooks] canEvaluatePolicy | policy: ' + policyName +
                                    ' | available: ' + canEval);
                        } catch (e) {
                            emitLog('[biometric_hooks] Error in canEvaluatePolicy hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[biometric_hooks] Failed to hook LAContext.canEvaluatePolicy: ' + e);
        }

        // LAContext.biometryType getter
        try {
            var LAContext3 = ObjC.classes.LAContext;
            if (LAContext3 && LAContext3['- biometryType']) {
                Interceptor.attach(LAContext3['- biometryType'].implementation, {
                    onLeave: function(retval) {
                        try {
                            var type = retval.toInt32();
                            var typeNames = { 0: 'None', 1: 'TouchID', 2: 'FaceID', 3: 'OpticID' };
                            var typeName = typeNames[type] || String(type);
                            emitLog('[biometric_hooks] LAContext.biometryType: ' + typeName);
                        } catch (e) { /* ignore */ }
                    }
                });
            }
        } catch (e) {
            emitLog('[biometric_hooks] Failed to hook LAContext.biometryType: ' + e);
        }

        // LAContext.setInteractionNotAllowed — silent/non-interactive auth attempt
        try {
            var LAContext4 = ObjC.classes.LAContext;
            if (LAContext4 && LAContext4['- setInteractionNotAllowed:']) {
                Interceptor.attach(LAContext4['- setInteractionNotAllowed:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var notAllowed = args[2].toInt32() !== 0;
                            if (notAllowed) {
                                emitLog('[biometric_hooks] LAContext.interactionNotAllowed=YES (silent auth)');
                                emitFinding(
                                    'Non-Interactive Biometric Auth Attempt',
                                    'INFO',
                                    'LAContext.interactionNotAllowed set to YES. The app attempts silent ' +
                                    'biometric auth without user interaction.',
                                    {
                                        platform: 'ios', component: 'LAContext',
                                        setting: 'interactionNotAllowed', value: true
                                    }
                                );
                            }
                        } catch (e) { /* ignore */ }
                    }
                });
            }
        } catch (e) {
            emitLog('[biometric_hooks] Failed to hook setInteractionNotAllowed: ' + e);
        }

        // SecAccessControlCreateWithFlags — detect Keychain-bound biometrics (strong path)
        try {
            var secACCreate = Module.findExportByName('Security', 'SecAccessControlCreateWithFlags');
            if (secACCreate) {
                Interceptor.attach(secACCreate, {
                    onEnter: function(args) {
                        try {
                            var flags = args[2].toInt32();
                            var flagNames = [];
                            if (flags & (1 << 0)) flagNames.push('userPresence');
                            if (flags & (1 << 1)) flagNames.push('biometryAny');
                            if (flags & (1 << 3)) flagNames.push('biometryCurrentSet');
                            if (flags & (1 << 4)) flagNames.push('devicePasscode');
                            if (flags & (1 << 5)) flagNames.push('watch');
                            if (flags & (1 << 14)) flagNames.push('privateKeyUsage');
                            if (flags & (1 << 16)) flagNames.push('applicationPassword');
                            var flagStr = flagNames.length > 0 ? flagNames.join('|') : 'none';

                            emitLog('[biometric_hooks] SecAccessControlCreateWithFlags | flags: ' + flagStr);

                            if (flagNames.indexOf('biometryAny') !== -1 ||
                                flagNames.indexOf('biometryCurrentSet') !== -1) {
                                emitFinding(
                                    'Keychain-Bound Biometric Authentication (Strong)',
                                    'INFO',
                                    'SecAccessControl created with biometric flags (' + flagStr + '). ' +
                                    'This binds biometric auth to Keychain item access, the strong and ' +
                                    'recommended approach that cannot be bypassed by hooking a callback.',
                                    {
                                        platform: 'ios', component: 'SecAccessControl',
                                        method: 'SecAccessControlCreateWithFlags',
                                        flags: flagStr, flags_raw: flags,
                                        auth_strength: 'strong', keychain_bound: true
                                    }
                                );
                            }
                        } catch (e) {
                            emitLog('[biometric_hooks] Error in SecAccessControlCreateWithFlags hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[biometric_hooks] Failed to hook SecAccessControlCreateWithFlags: ' + e);
        }

        // LAContext.evaluateAccessControl — Keychain-bound biometric operation
        try {
            var LAContext5 = ObjC.classes.LAContext;
            if (LAContext5 && LAContext5['- evaluateAccessControl:operation:localizedReason:reply:']) {
                Interceptor.attach(LAContext5['- evaluateAccessControl:operation:localizedReason:reply:'].implementation, {
                    onEnter: function(args) {
                        try {
                            var op = args[3].toInt32();
                            var opNames = {
                                1: 'UseItem', 2: 'CreateItem', 3: 'UseKeySign',
                                4: 'UseKeyDecrypt', 5: 'UseKeyKeyExchange'
                            };
                            var reason = ObjC.Object(args[4]).toString();
                            var opName = opNames[op] || String(op);
                            emitLog('[biometric_hooks] evaluateAccessControl | op: ' + opName +
                                    ' | reason: ' + reason);
                        } catch (e) {
                            emitLog('[biometric_hooks] Error in evaluateAccessControl hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[biometric_hooks] Failed to hook evaluateAccessControl: ' + e);
        }

        emitLog('[biometric_hooks] iOS biometric hooks attached');
    }
})();
