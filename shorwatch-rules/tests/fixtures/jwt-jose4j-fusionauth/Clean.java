package com.example.jose;

import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.hmac.HMACSigner;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

public class Clean {
    void symmetric(JsonWebSignature jws, JsonWebEncryption jwe) {
        // HMAC and AES-256 key wrapping are symmetric: not affected by Shor.
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
    }

    Object fusionAuth(String secret) {
        HMACSigner.newSHA256Signer(secret);
        return Algorithm.HS256;
    }
}
