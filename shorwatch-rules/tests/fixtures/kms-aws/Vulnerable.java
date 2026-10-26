package com.example.signing;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/** Document signing with an asymmetric KMS key. */
public class Vulnerable {
    private final KmsClient kms = KmsClient.create();

    String createKey() {
        return kms.createKey(CreateKeyRequest.builder()
                        .keySpec(KeySpec.RSA_3072)
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .build())
                .keyMetadata()
                .keyId();
    }

    SdkBytes sign(String keyId, SdkBytes digest) {
        return kms.sign(SignRequest.builder()
                        .keyId(keyId)
                        .message(digest)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build())
                .signature();
    }

    KeySpec legacySdk() {
        return KeySpec.ECC_NIST_P256;
    }
}
