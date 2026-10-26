package com.example.vault;

import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.models.CreateOctKeyOptions;

public class Clean {
    byte[] symmetric(KeyClient keys, CryptographyClient crypto, byte[] data) {
        keys.createOctKey(new CreateOctKeyOptions("data").setKeySize(256));
        return crypto.encrypt(EncryptionAlgorithm.A256GCM, data).getCipherText();
    }
}
