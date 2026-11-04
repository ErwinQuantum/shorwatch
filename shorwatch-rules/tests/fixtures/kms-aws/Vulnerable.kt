package com.example.signing

import software.amazon.awssdk.core.SdkBytes
import software.amazon.awssdk.services.kms.KmsClient
import software.amazon.awssdk.services.kms.model.CreateKeyRequest
import software.amazon.awssdk.services.kms.model.DeriveSharedSecretRequest
import software.amazon.awssdk.services.kms.model.KeyAgreementAlgorithmSpec
import software.amazon.awssdk.services.kms.model.KeySpec
import software.amazon.awssdk.services.kms.model.KeyUsageType
import software.amazon.awssdk.services.kms.model.SignRequest
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec

/** Document signing with an asymmetric KMS key. */
class Vulnerable {
    private val kms = KmsClient.create()

    fun createKey(): String = kms.createKey(
        CreateKeyRequest.builder()
            .keySpec(KeySpec.RSA_3072)
            .keyUsage(KeyUsageType.SIGN_VERIFY)
            .build(),
    ).keyMetadata().keyId()

    fun sign(keyId: String, digest: SdkBytes): SdkBytes = kms.sign(
        SignRequest.builder()
            .keyId(keyId)
            .message(digest)
            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
            .build(),
    ).signature()

    fun legacySdk(): KeySpec = KeySpec.ECC_NIST_P256

    /** Key agreement: KMS derives the shared secret with its ECC key. */
    fun agreement(keyId: String, peerPublicKey: SdkBytes): DeriveSharedSecretRequest =
        DeriveSharedSecretRequest.builder()
            .keyId(keyId)
            .keyAgreementAlgorithm(KeyAgreementAlgorithmSpec.ECDH)
            .publicKey(peerPublicKey)
            .build()
}
