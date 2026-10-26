package com.example.vault;

import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.CreateEcKeyOptions;
import com.azure.security.keyvault.keys.models.KeyCurveName;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

public class Vulnerable {
    KeyVaultKey rsaKey(KeyClient keys) {
        return keys.createRsaKey(new com.azure.security.keyvault.keys.models.CreateRsaKeyOptions("signing"));
    }

    KeyVaultKey ecKey(KeyClient keys) {
        // Two findings: the EC key options and the curve.
        return keys.createEcKey(new CreateEcKeyOptions("agreement").setCurveName(KeyCurveName.P_256));
    }

    byte[] sign(CryptographyClient crypto, byte[] digest) {
        return crypto.sign(SignatureAlgorithm.ES256, digest).getSignature();
    }

    byte[] wrap(CryptographyClient crypto, byte[] key) {
        crypto.encrypt(EncryptionAlgorithm.A128GCM, key);
        return crypto.encrypt(EncryptionAlgorithm.RSA_OAEP_256, key).getCipherText();
    }
}
