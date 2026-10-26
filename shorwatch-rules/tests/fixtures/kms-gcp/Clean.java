package com.example.kms;

import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;

public class Clean {
    Object[] safe() {
        return new Object[] {
            CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION, CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65,
        };
    }
}
