package com.example.kms

import com.google.cloud.kms.v1.CryptoKey
import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm
import com.google.cloud.kms.v1.CryptoKeyVersionTemplate

class Vulnerable {
    fun signingKey(): CryptoKey = CryptoKey.newBuilder()
        .setPurpose(CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN)
        .setVersionTemplate(
            CryptoKeyVersionTemplate.newBuilder()
                .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256),
        )
        .build()

    fun others(): List<Any> = listOf(
        CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_3072_SHA256,
        CryptoKeyVersionAlgorithm.EC_SIGN_ED25519,
    )
}
