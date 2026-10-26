package com.example.signing;

import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

public class Clean {
    Object[] postQuantum() {
        return new Object[] {KeySpec.ML_DSA_65, SigningAlgorithmSpec.ML_DSA_SHAKE_256, KeySpec.SYMMETRIC_DEFAULT};
    }
}
