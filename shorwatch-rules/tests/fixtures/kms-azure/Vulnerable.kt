package com.example.vault

import com.azure.security.keyvault.keys.KeyClient
import com.azure.security.keyvault.keys.cryptography.CryptographyClient
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm
import com.azure.security.keyvault.keys.models.CreateEcKeyOptions
import com.azure.security.keyvault.keys.models.KeyCurveName
import com.azure.security.keyvault.keys.models.KeyVaultKey

class Vulnerable {
    fun rsaKey(keys: KeyClient): KeyVaultKey =
        keys.createRsaKey(com.azure.security.keyvault.keys.models.CreateRsaKeyOptions("signing"))

    // Two findings: the EC key options and the curve.
    fun ecKey(keys: KeyClient): KeyVaultKey =
        keys.createEcKey(CreateEcKeyOptions("agreement").setCurveName(KeyCurveName.P_256))

    fun sign(crypto: CryptographyClient, digest: ByteArray): ByteArray =
        crypto.sign(SignatureAlgorithm.ES256, digest).signature

    fun wrap(crypto: CryptographyClient, key: ByteArray): ByteArray {
        crypto.encrypt(EncryptionAlgorithm.A128GCM, key)
        return crypto.encrypt(EncryptionAlgorithm.RSA_OAEP_256, key).cipherText
    }
}
