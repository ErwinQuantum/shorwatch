package com.example.legacy;

import java.security.AlgorithmParameterGenerator;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.jce.spec.ElGamalGenParameterSpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

public class Vulnerable {
    Cipher provider() throws Exception {
        KeyPairGenerator.getInstance("ElGamal", "BC");
        return Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC");
    }

    Object lightweight() {
        new ElGamalKeyPairGenerator();
        return new ElGamalEngine();
    }

    // The group of the provider-level key generator, and its own generator.
    Object parameters() throws Exception {
        AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
        new ElGamalGenParameterSpec(1024);
        return new ElGamalParameterSpec(null, null);
    }
}
