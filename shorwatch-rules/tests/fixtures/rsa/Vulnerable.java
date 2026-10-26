package com.example.legacy;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.engines.RSAEngine;

public class Vulnerable {
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    KeyPair generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        return generator.generateKeyPair();
    }

    byte[] encrypt(KeyPair pair, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        return cipher.doFinal(data);
    }

    byte[] sign(KeyPair pair, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(pair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    Object factory() throws Exception {
        return KeyFactory.getInstance("rsa");
    }

    Object lightweight() {
        return new RSAEngine();
    }

    void commentedOut() throws Exception {
        // KeyPairGenerator.getInstance("RSA");
        /* Cipher.getInstance("RSA/ECB/PKCS1Padding"); */
    }
}
