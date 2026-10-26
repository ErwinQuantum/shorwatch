package com.example.transfer;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

public class Clean {
    Object symmetric() {
        // AES-256 and SHA-256 are fine; the key algorithm is not visible here.
        return new Object[] {
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256), HashAlgorithmTags.SHA256,
        };
    }
}
