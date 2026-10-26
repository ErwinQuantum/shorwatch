package com.example.transfer

import java.security.KeyPair
import java.util.Date
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder

/** Encrypting and signing files for a partner over SFTP, the classic PGP setup. */
class Vulnerable {
    fun signingKey(keys: KeyPair): PGPKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keys, Date())

    fun agreementKey(keys: KeyPair): PGPKeyPair = JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, keys, Date())

    /** Two findings: ECDSA and SHA-1. */
    fun signer() = JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA, HashAlgorithmTags.SHA1)

    fun legacyEncryption(): JcePGPDataEncryptorBuilder {
        JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES)
        return JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128)
    }
}
