package com.example.kms

import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm

class Clean {
    fun safe(): List<Any> = listOf(
        CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
        CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65,
    )
}
