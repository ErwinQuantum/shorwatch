package com.example.tokens;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.SignatureKeyTemplates;

public class Vulnerable {
    KeysetHandle signing() throws Exception {
        return KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519);
    }

    KeysetHandle byName() throws Exception {
        KeysetHandle.generateNew(KeyTemplates.get("JWT_ES256"));
        KeysetHandle.generateNew(KeyTemplates.get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM"));
        return KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM"));
    }

    Object ecdsa() throws Exception {
        KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
        KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
        return KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256);
    }

    Object legacy() {
        return new Object[] {
            SignatureKeyTemplates.RSA_SSA_PKCS1_3072_SHA256_F4,
            HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
        };
    }
}
