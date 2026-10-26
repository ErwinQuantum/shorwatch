package com.example.vault

import com.azure.security.keyvault.keys.KeyClient
import com.azure.security.keyvault.keys.cryptography.CryptographyClient
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm
import com.azure.security.keyvault.keys.models.CreateOctKeyOptions

class Clean {
    fun symmetric(keys: KeyClient, crypto: CryptographyClient, data: ByteArray): ByteArray {
        keys.createOctKey(CreateOctKeyOptions("data").setKeySize(256))
        return crypto.encrypt(EncryptionAlgorithm.A256GCM, data).cipherText
    }
}
