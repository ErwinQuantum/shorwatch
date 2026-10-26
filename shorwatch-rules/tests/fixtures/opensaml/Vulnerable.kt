package com.example.sso

import org.opensaml.xmlsec.encryption.support.EncryptionConstants
import org.opensaml.xmlsec.signature.support.SignatureConstants

/** SAML identity provider: assertion signing and encryption algorithms. */
class Vulnerable {
    fun signatureAlgorithm(): String = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256

    /** Two findings: ECDSA and SHA-1. */
    fun legacySignature(): String = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1

    fun encryption(): Array<String> = arrayOf(
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
        EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
    )
}
