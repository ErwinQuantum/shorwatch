package com.example.legacy;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;

interface Algorithms {
    String KEY_AGREEMENT = "DiffieHellman";
}

public class Vulnerable {
    KeyPair generate(BigInteger p, BigInteger g) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
        generator.initialize(new DHParameterSpec(p, g));
        return generator.generateKeyPair();
    }

    byte[] agree(KeyPair mine, java.security.PublicKey theirs) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance(Algorithms.KEY_AGREEMENT);
        agreement.init(mine.getPrivate());
        agreement.doPhase(theirs, true);
        return agreement.generateSecret();
    }

    Object lightweight() {
        return new DHBasicAgreement();
    }
}
