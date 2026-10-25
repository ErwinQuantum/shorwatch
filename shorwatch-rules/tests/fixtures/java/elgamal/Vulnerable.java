package com.example.legacy;

import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;

public class Vulnerable {
    Cipher provider() throws Exception {
        KeyPairGenerator.getInstance("ElGamal", "BC");
        return Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC");
    }

    Object lightweight() {
        new ElGamalKeyPairGenerator();
        return new ElGamalEngine();
    }
}
