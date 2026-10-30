/*
 * crypto_hooks.js — Cryptographic operation monitoring
 * Platform: Android + iOS
 * Purpose:  Log encryption/decryption/hashing operations to detect weak crypto
 * MASVS:   MASVS-CRYPTO-1, MASVS-CRYPTO-2
 */

"use strict";

function _send(op, algo, keyLen, detail) {
    send({ type: "crypto_hook", operation: op, algorithm: algo || "",
           key_length: keyLen || 0, detail: detail || "" });
}

// ── Android ────────────────────────────────────────────────────────────

if (Java.available) {
    Java.perform(function () {

        // 1. Cipher.getInstance — track algorithm selection
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            Cipher.getInstance.overload("java.lang.String").implementation = function (transform) {
                _send("cipher_init", transform, 0, "Cipher.getInstance(\"" + transform + "\")");
                return this.getInstance(transform);
            };
            Cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (transform, provider) {
                _send("cipher_init", transform, 0, "Cipher.getInstance(\"" + transform + "\", \"" + provider + "\")");
                return this.getInstance(transform, provider);
            };
        } catch (e) { /* skip */ }

        // 2. Cipher.init — capture key size
        try {
            var Cipher2 = Java.use("javax.crypto.Cipher");
            Cipher2.init.overload("int", "java.security.Key").implementation = function (mode, key) {
                var algo = this.getAlgorithm();
                var kLen = 0;
                try { kLen = key.getEncoded().length * 8; } catch (e2) {}
                var modeStr = mode === 1 ? "ENCRYPT" : mode === 2 ? "DECRYPT" : String(mode);
                _send("cipher_use", algo, kLen, "Cipher.init(" + modeStr + ", keyLen=" + kLen + ")");
                return this.init(mode, key);
            };
        } catch (e) { /* skip */ }

        // 3. MessageDigest.getInstance — track hash algorithms
        try {
            var MD = Java.use("java.security.MessageDigest");
            MD.getInstance.overload("java.lang.String").implementation = function (algo) {
                _send("hash", algo, 0, "MessageDigest.getInstance(\"" + algo + "\")");
                return this.getInstance(algo);
            };
        } catch (e) { /* skip */ }

        // 4. Mac.getInstance — HMAC algorithm tracking
        try {
            var Mac = Java.use("javax.crypto.Mac");
            Mac.getInstance.overload("java.lang.String").implementation = function (algo) {
                _send("mac", algo, 0, "Mac.getInstance(\"" + algo + "\")");
                return this.getInstance(algo);
            };
        } catch (e) { /* skip */ }

        // 5. SecretKeySpec — detect hardcoded keys
        try {
            var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
            SKS.$init.overload("[B", "java.lang.String").implementation = function (keyBytes, algo) {
                var kLen = keyBytes ? keyBytes.length * 8 : 0;
                _send("key_creation", algo, kLen, "SecretKeySpec(keyLen=" + kLen + ", algo=\"" + algo + "\")");
                return this.$init(keyBytes, algo);
            };
        } catch (e) { /* skip */ }

        // 6. KeyGenerator.init — key generation parameters
        try {
            var KG = Java.use("javax.crypto.KeyGenerator");
            KG.init.overload("int").implementation = function (keySize) {
                var algo = this.getAlgorithm();
                _send("keygen", algo, keySize, "KeyGenerator.init(keySize=" + keySize + ")");
                return this.init(keySize);
            };
        } catch (e) { /* skip */ }

        // 7. PBEKeySpec — password-based key derivation
        try {
            var PBE = Java.use("javax.crypto.spec.PBEKeySpec");
            PBE.$init.overload("[C", "[B", "int", "int").implementation = function (pw, salt, iter, keyLen) {
                _send("pbkdf", "PBKDF2", keyLen,
                    "PBEKeySpec(saltLen=" + (salt ? salt.length : 0) +
                    ", iterations=" + iter + ", keyLen=" + keyLen + ")");
                return this.$init(pw, salt, iter, keyLen);
            };
        } catch (e) { /* skip */ }

        // 8. SecureRandom — track PRNG usage
        try {
            var SR = Java.use("java.security.SecureRandom");
            SR.setSeed.overload("[B").implementation = function (seed) {
                _send("prng_seed", "SecureRandom", seed ? seed.length * 8 : 0,
                    "SecureRandom.setSeed(len=" + (seed ? seed.length : 0) + ")");
                return this.setSeed(seed);
            };
        } catch (e) { /* skip */ }

        // 9. KeyStore — key storage operations
        try {
            var KS = Java.use("java.security.KeyStore");
            KS.getInstance.overload("java.lang.String").implementation = function (type) {
                _send("keystore", type, 0, "KeyStore.getInstance(\"" + type + "\")");
                return this.getInstance(type);
            };
        } catch (e) { /* skip */ }

        // 10. IvParameterSpec — detect static/empty IVs
        try {
            var IVSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            IVSpec.$init.overload("[B").implementation = function (iv) {
                var allZero = true;
                if (iv) {
                    for (var i = 0; i < iv.length; i++) {
                        if (iv[i] !== 0) { allZero = false; break; }
                    }
                }
                if (allZero && iv && iv.length > 0) {
                    _send("weak_iv", "IvParameterSpec", iv.length * 8,
                        "IvParameterSpec with all-zero IV (len=" + iv.length + ")");
                } else {
                    _send("iv", "IvParameterSpec", iv ? iv.length * 8 : 0,
                        "IvParameterSpec(len=" + (iv ? iv.length : 0) + ")");
                }
                return this.$init(iv);
            };
        } catch (e) { /* skip */ }
    });
}

// ── iOS ────────────────────────────────────────────────────────────────

if (ObjC.available) {

    // 1. CCCrypt — CommonCrypto main entry
    try {
        var ccCryptAddr = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
        if (ccCryptAddr) {
            var algNames = { 0: "AES", 1: "DES", 2: "3DES", 3: "CAST", 4: "RC4", 5: "RC2", 6: "Blowfish" };
            Interceptor.attach(ccCryptAddr, {
                onEnter: function (args) {
                    var op = args[0].toInt32();
                    var alg = args[1].toInt32();
                    var keyLen = args[4].toInt32();
                    var opStr = op === 0 ? "ENCRYPT" : "DECRYPT";
                    var algStr = algNames[alg] || ("algo_" + alg);
                    _send("cccrypt_" + opStr.toLowerCase(), algStr, keyLen * 8,
                        "CCCrypt(" + opStr + ", " + algStr + ", keyLen=" + (keyLen * 8) + ")");
                }
            });
        }
    } catch (e) { /* skip */ }

    // 2. CCHmac — HMAC operations
    try {
        var ccHmacAddr = Module.findExportByName("libcommonCrypto.dylib", "CCHmac");
        if (ccHmacAddr) {
            var hmacAlgs = { 0: "SHA1", 1: "MD5", 2: "SHA256", 3: "SHA384", 4: "SHA512", 5: "SHA224" };
            Interceptor.attach(ccHmacAddr, {
                onEnter: function (args) {
                    var alg = args[0].toInt32();
                    var keyLen = args[2].toInt32();
                    _send("hmac", hmacAlgs[alg] || ("alg_" + alg), keyLen * 8,
                        "CCHmac(" + (hmacAlgs[alg] || alg) + ", keyLen=" + (keyLen * 8) + ")");
                }
            });
        }
    } catch (e) { /* skip */ }

    // 3. CC_MD5 / CC_SHA1 — weak hash detection
    ["CC_MD5", "CC_SHA1", "CC_SHA256", "CC_SHA512"].forEach(function (fn) {
        try {
            var addr = Module.findExportByName("libcommonCrypto.dylib", fn);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        var dataLen = args[1].toInt32();
                        _send("hash", fn.replace("CC_", ""), 0,
                            fn + "(dataLen=" + dataLen + ")");
                    }
                });
            }
        } catch (e) { /* skip */ }
    });

    // 4. SecKeyCreateRandomKey — key generation
    try {
        var skAddr = Module.findExportByName("Security", "SecKeyCreateRandomKey");
        if (skAddr) {
            Interceptor.attach(skAddr, {
                onEnter: function (args) {
                    _send("keygen", "SecKey", 0, "SecKeyCreateRandomKey called");
                }
            });
        }
    } catch (e) { /* skip */ }

    // 5. SecKeyEncrypt / SecKeyDecrypt
    ["SecKeyEncrypt", "SecKeyDecrypt"].forEach(function (fn) {
        try {
            var addr = Module.findExportByName("Security", fn);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        var plainLen = args[3].toInt32();
                        _send(fn.toLowerCase().replace("seckey", ""), "SecKey", 0,
                            fn + "(dataLen=" + plainLen + ")");
                    }
                });
            }
        } catch (e) { /* skip */ }
    });

    // 6. CCKeyDerivationPBKDF — PBKDF2 on iOS
    try {
        var pbkdfAddr = Module.findExportByName("libcommonCrypto.dylib", "CCKeyDerivationPBKDF");
        if (pbkdfAddr) {
            Interceptor.attach(pbkdfAddr, {
                onEnter: function (args) {
                    var rounds = args[6].toInt32();
                    var dkLen = args[8].toInt32();
                    _send("pbkdf", "PBKDF2", dkLen * 8,
                        "CCKeyDerivationPBKDF(rounds=" + rounds + ", dkLen=" + (dkLen * 8) + ")");
                }
            });
        }
    } catch (e) { /* skip */ }
}

send({ type: "crypto_hook", operation: "init", algorithm: "", key_length: 0, detail: "Crypto hooks installed" });
