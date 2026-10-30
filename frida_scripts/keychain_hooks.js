(function() {
    'use strict';

    var CATALOGUE_ID = 'QUILL-INS-007';

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

    // ── iOS Keychain constants ──

    var ACCESSIBILITY_MAP = {
        'ak':   'kSecAttrAccessibleWhenUnlocked',
        'ck':   'kSecAttrAccessibleAfterFirstUnlock',
        'dk':   'kSecAttrAccessibleAlways',
        'aku':  'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
        'cku':  'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
        'dku':  'kSecAttrAccessibleAlwaysThisDeviceOnly',
        'akpu': 'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly'
    };

    var INSECURE_ACCESSIBILITY = [
        'kSecAttrAccessibleAlways',
        'kSecAttrAccessibleAlwaysThisDeviceOnly'
    ];

    var SEC_CLASS_MAP = {
        'genp': 'kSecClassGenericPassword',
        'inet': 'kSecClassInternetPassword',
        'cert': 'kSecClassCertificate',
        'keys': 'kSecClassKey',
        'idnt': 'kSecClassIdentity'
    };

    function resolveAccessibility(value) {
        if (!value) return 'not set';
        var s = String(value);
        return ACCESSIBILITY_MAP[s] || s;
    }

    function resolveSecClass(value) {
        if (!value) return 'unknown';
        var s = String(value);
        return SEC_CLASS_MAP[s] || s;
    }

    function dictToObj(ptr) {
        var result = {};
        if (!ptr || ptr.isNull()) return result;
        try {
            var nsDict = ObjC.Object(ptr);
            var keys = nsDict.allKeys();
            var count = keys.count();
            for (var i = 0; i < count; i++) {
                var key = keys.objectAtIndex_(i).toString();
                var val = nsDict.objectForKey_(keys.objectAtIndex_(i));
                if (val && !val.isNull()) {
                    result[key] = val.toString();
                }
            }
        } catch (e) { /* best effort */ }
        return result;
    }

    // ── iOS hooks ──

    if (ObjC && ObjC.available) {
        emitLog('[keychain_hooks] Attaching iOS Keychain hooks');

        // SecItemAdd
        try {
            var secItemAdd = Module.findExportByName('Security', 'SecItemAdd');
            if (secItemAdd) {
                Interceptor.attach(secItemAdd, {
                    onEnter: function(args) {
                        try {
                            var query = dictToObj(args[0]);
                            var service = query['svce'] || query['kSecAttrService'] || 'unknown';
                            var secClass = resolveSecClass(query['class'] || query['kSecClass']);
                            var accessibility = resolveAccessibility(query['pdmn'] || query['kSecAttrAccessible']);
                            var account = query['acct'] || query['kSecAttrAccount'] || '';
                            var hasACL = query['accc'] !== undefined;

                            emitLog('[keychain_hooks] SecItemAdd | service: ' + service +
                                    ' | class: ' + secClass + ' | accessible: ' + accessibility +
                                    ' | account: ' + account + ' | hasACL: ' + hasACL);

                            if (INSECURE_ACCESSIBILITY.indexOf(accessibility) !== -1) {
                                emitFinding(
                                    'Insecure Keychain Accessibility (SecItemAdd)',
                                    'HIGH',
                                    'The application stores a keychain item with accessibility set to ' +
                                    accessibility + '. This deprecated setting allows access even when the ' +
                                    'device is locked, weakening protection of stored secrets.',
                                    {
                                        platform: 'ios',
                                        operation: 'SecItemAdd',
                                        service: service,
                                        sec_class: secClass,
                                        accessibility: accessibility,
                                        account: account,
                                        has_acl: hasACL
                                    }
                                );
                            }

                            if (accessibility === 'not set') {
                                emitFinding(
                                    'Keychain Item Without Explicit Accessibility',
                                    'MEDIUM',
                                    'A keychain item was stored without specifying kSecAttrAccessible. ' +
                                    'The default may vary by iOS version and could be less restrictive than intended.',
                                    {
                                        platform: 'ios',
                                        operation: 'SecItemAdd',
                                        service: service,
                                        sec_class: secClass,
                                        accessibility: 'default (not explicitly set)',
                                        account: account
                                    }
                                );
                            }
                        } catch (e) {
                            emitLog('[keychain_hooks] Error in SecItemAdd hook: ' + e);
                        }
                    },
                    onLeave: function(retval) {
                        var status = retval.toInt32();
                        if (status !== 0) {
                            emitLog('[keychain_hooks] SecItemAdd returned error: ' + status);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[keychain_hooks] Failed to hook SecItemAdd: ' + e);
        }

        // SecItemCopyMatching
        try {
            var secItemCopy = Module.findExportByName('Security', 'SecItemCopyMatching');
            if (secItemCopy) {
                Interceptor.attach(secItemCopy, {
                    onEnter: function(args) {
                        try {
                            var query = dictToObj(args[0]);
                            var service = query['svce'] || query['kSecAttrService'] || 'unknown';
                            var secClass = resolveSecClass(query['class'] || query['kSecClass']);
                            var account = query['acct'] || query['kSecAttrAccount'] || '';
                            var accessible = resolveAccessibility(query['pdmn'] || query['kSecAttrAccessible']);
                            emitLog('[keychain_hooks] SecItemCopyMatching | service: ' + service +
                                    ' | class: ' + secClass + ' | account: ' + account +
                                    ' | accessible: ' + accessible);
                        } catch (e) {
                            emitLog('[keychain_hooks] Error in SecItemCopyMatching hook: ' + e);
                        }
                    },
                    onLeave: function(retval) {
                        var status = retval.toInt32();
                        emitLog('[keychain_hooks] SecItemCopyMatching result: ' +
                                (status === 0 ? 'found' : 'status ' + status));
                    }
                });
            }
        } catch (e) {
            emitLog('[keychain_hooks] Failed to hook SecItemCopyMatching: ' + e);
        }

        // SecItemUpdate
        try {
            var secItemUpdate = Module.findExportByName('Security', 'SecItemUpdate');
            if (secItemUpdate) {
                Interceptor.attach(secItemUpdate, {
                    onEnter: function(args) {
                        try {
                            var query = dictToObj(args[0]);
                            var update = dictToObj(args[1]);
                            var service = query['svce'] || query['kSecAttrService'] || 'unknown';
                            var account = query['acct'] || query['kSecAttrAccount'] || '';
                            var newAccessibility = resolveAccessibility(update['pdmn'] || update['kSecAttrAccessible']);

                            emitLog('[keychain_hooks] SecItemUpdate | service: ' + service +
                                    ' | account: ' + account + ' | new accessible: ' + newAccessibility);

                            if (INSECURE_ACCESSIBILITY.indexOf(newAccessibility) !== -1) {
                                emitFinding(
                                    'Insecure Keychain Accessibility (SecItemUpdate)',
                                    'HIGH',
                                    'A keychain item was updated to use accessibility ' + newAccessibility +
                                    ', making it accessible when the device is locked.',
                                    {
                                        platform: 'ios',
                                        operation: 'SecItemUpdate',
                                        service: service,
                                        account: account,
                                        new_accessibility: newAccessibility
                                    }
                                );
                            }
                        } catch (e) {
                            emitLog('[keychain_hooks] Error in SecItemUpdate hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[keychain_hooks] Failed to hook SecItemUpdate: ' + e);
        }

        // SecItemDelete
        try {
            var secItemDelete = Module.findExportByName('Security', 'SecItemDelete');
            if (secItemDelete) {
                Interceptor.attach(secItemDelete, {
                    onEnter: function(args) {
                        try {
                            var query = dictToObj(args[0]);
                            var service = query['svce'] || query['kSecAttrService'] || 'unknown';
                            var secClass = resolveSecClass(query['class'] || query['kSecClass']);
                            var account = query['acct'] || query['kSecAttrAccount'] || '';
                            emitLog('[keychain_hooks] SecItemDelete | service: ' + service +
                                    ' | class: ' + secClass + ' | account: ' + account);
                        } catch (e) {
                            emitLog('[keychain_hooks] Error in SecItemDelete hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[keychain_hooks] Failed to hook SecItemDelete: ' + e);
        }

        // SecAccessControlCreateWithFlags — biometric/passcode access control
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
                            emitLog('[keychain_hooks] SecAccessControlCreateWithFlags | flags: ' + flagStr);
                        } catch (e) {
                            emitLog('[keychain_hooks] Error in SecAccessControlCreateWithFlags hook: ' + e);
                        }
                    }
                });
            }
        } catch (e) {
            emitLog('[keychain_hooks] Failed to hook SecAccessControlCreateWithFlags: ' + e);
        }

        emitLog('[keychain_hooks] iOS Keychain hooks attached');
    }

    // ── Android KeyStore hooks ──

    if (Java && Java.available) {
        Java.perform(function() {
            emitLog('[keychain_hooks] Attaching Android KeyStore hooks');

            // KeyStore.getInstance
            try {
                var KeyStore = Java.use('java.security.KeyStore');
                KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
                    emitLog('[keychain_hooks] KeyStore.getInstance | type: ' + type);
                    return this.getInstance(type);
                };
            } catch (e) {
                emitLog('[keychain_hooks] Failed to hook KeyStore.getInstance(String): ' + e);
            }

            try {
                var KeyStore1b = Java.use('java.security.KeyStore');
                KeyStore1b.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function(type, provider) {
                    emitLog('[keychain_hooks] KeyStore.getInstance | type: ' + type + ' | provider: ' + provider);
                    return this.getInstance(type, provider);
                };
            } catch (e) {
                emitLog('[keychain_hooks] Failed to hook KeyStore.getInstance(String, String): ' + e);
            }

            // KeyStore.getEntry
            try {
                var KeyStore2 = Java.use('java.security.KeyStore');
                KeyStore2.getEntry.implementation = function(alias, protParam) {
                    try {
                        var hasProtection = protParam !== null;
                        var entry = this.getEntry(alias, protParam);
                        var entryType = entry ? entry.getClass().getName() : 'null';
                        emitLog('[keychain_hooks] KeyStore.getEntry | alias: ' + alias +
                                ' | type: ' + entryType + ' | protected: ' + hasProtection);
                        if (!hasProtection) {
                            emitFinding(
                                'KeyStore Entry Retrieved Without Protection Parameter',
                                'MEDIUM',
                                'KeyStore entry "' + alias + '" retrieved without a ProtectionParameter. ' +
                                'The key may not require user authentication to access.',
                                {
                                    platform: 'android',
                                    operation: 'KeyStore.getEntry',
                                    alias: String(alias),
                                    entry_type: entryType,
                                    protection_param: false
                                }
                            );
                        }
                        return entry;
                    } catch (e) {
                        emitLog('[keychain_hooks] Error in getEntry hook: ' + e);
                        return this.getEntry(alias, protParam);
                    }
                };
            } catch (e) {
                emitLog('[keychain_hooks] Failed to hook KeyStore.getEntry: ' + e);
            }

            // KeyStore.setEntry
            try {
                var KeyStore3 = Java.use('java.security.KeyStore');
                KeyStore3.setEntry.implementation = function(alias, entry, protParam) {
                    try {
                        var entryType = entry ? entry.getClass().getName() : 'null';
                        var hasProtection = protParam !== null;
                        emitLog('[keychain_hooks] KeyStore.setEntry | alias: ' + alias +
                                ' | type: ' + entryType + ' | protected: ' + hasProtection);
                        if (!hasProtection) {
                            emitFinding(
                                'KeyStore Entry Stored Without Protection Parameter',
                                'MEDIUM',
                                'KeyStore entry "' + alias + '" stored without a ProtectionParameter. ' +
                                'The key material may not require user authentication.',
                                {
                                    platform: 'android',
                                    operation: 'KeyStore.setEntry',
                                    alias: String(alias),
                                    entry_type: entryType,
                                    protection_param: false
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[keychain_hooks] Error in setEntry hook: ' + e);
                    }
                    return this.setEntry(alias, entry, protParam);
                };
            } catch (e) {
                emitLog('[keychain_hooks] Failed to hook KeyStore.setEntry: ' + e);
            }

            // KeyStore.deleteEntry
            try {
                var KeyStore4 = Java.use('java.security.KeyStore');
                KeyStore4.deleteEntry.implementation = function(alias) {
                    emitLog('[keychain_hooks] KeyStore.deleteEntry | alias: ' + alias);
                    return this.deleteEntry(alias);
                };
            } catch (e) {
                emitLog('[keychain_hooks] Failed to hook KeyStore.deleteEntry: ' + e);
            }

            // KeyGenParameterSpec.Builder.build — capture key generation protection parameters
            try {
                var KGPSBuilder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
                KGPSBuilder.build.implementation = function() {
                    var spec = this.build();
                    try {
                        var alias = spec.getKeystoreAlias();
                        var userAuthRequired = spec.isUserAuthenticationRequired();
                        var authTimeout = spec.getUserAuthenticationValidityDurationSeconds();
                        var biometricPresence = false;
                        try { biometricPresence = spec.isUserPresenceRequired(); } catch (e) {}
                        var invalidatedByBiometric = false;
                        try { invalidatedByBiometric = spec.isInvalidatedByBiometricEnrollment(); } catch (e) {}

                        emitLog('[keychain_hooks] KeyGenParameterSpec.build | alias: ' + alias +
                                ' | userAuth: ' + userAuthRequired +
                                ' | authTimeout: ' + authTimeout + 's' +
                                ' | biometric: ' + biometricPresence +
                                ' | invalidatedByBiometric: ' + invalidatedByBiometric);

                        if (!userAuthRequired) {
                            emitFinding(
                                'Key Generated Without User Authentication Requirement',
                                'MEDIUM',
                                'Cryptographic key "' + alias + '" generated without requiring user ' +
                                'authentication. The key can be used without biometric or lock screen verification.',
                                {
                                    platform: 'android',
                                    operation: 'KeyGenParameterSpec.build',
                                    alias: String(alias),
                                    user_auth_required: false,
                                    auth_timeout_seconds: authTimeout,
                                    biometric_presence: biometricPresence
                                }
                            );
                        }

                        if (userAuthRequired && authTimeout > 300) {
                            emitFinding(
                                'Key Authentication Validity Too Long',
                                'LOW',
                                'Cryptographic key "' + alias + '" has authentication validity of ' +
                                authTimeout + ' seconds (' + Math.round(authTimeout / 60) +
                                ' minutes). Consider reducing for sensitive operations.',
                                {
                                    platform: 'android',
                                    operation: 'KeyGenParameterSpec.build',
                                    alias: String(alias),
                                    user_auth_required: true,
                                    auth_timeout_seconds: authTimeout
                                }
                            );
                        }
                    } catch (e) {
                        emitLog('[keychain_hooks] Error inspecting KeyGenParameterSpec: ' + e);
                    }
                    return spec;
                };
            } catch (e) {
                emitLog('[keychain_hooks] Failed to hook KeyGenParameterSpec.Builder: ' + e);
            }

            // EncryptedSharedPreferences (Jetpack Security)
            try {
                var ESP = Java.use('androidx.security.crypto.EncryptedSharedPreferences');
                ESP.create.overload(
                    'java.lang.String', 'java.lang.String', 'android.content.Context',
                    'androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme',
                    'androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme'
                ).implementation = function(fileName, masterKeyAlias, context, keyScheme, valueScheme) {
                    emitLog('[keychain_hooks] EncryptedSharedPreferences.create | file: ' +
                            fileName + ' | masterKey: ' + masterKeyAlias);
                    return this.create(fileName, masterKeyAlias, context, keyScheme, valueScheme);
                };
            } catch (e) {
                emitLog('[keychain_hooks] Failed to hook EncryptedSharedPreferences: ' + e);
            }

            emitLog('[keychain_hooks] Android KeyStore hooks attached');
        });
    }
})();
