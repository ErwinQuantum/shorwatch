package com.example.payments;

import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;

/** Algorithms that reach the crypto API through variables, parameters and returns. */
public class Vulnerable {
    private final String transformation;

    Vulnerable(boolean legacy) {
        this.transformation = legacy ? "RSA/ECB/PKCS1Padding" : "AES/GCM/NoPadding";
    }

    byte[] sign(byte[] data, String algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        signature.update(data);
        return signature.sign();
    }

    /** Two findings at `getInstance`: RSA and SHA-1. */
    byte[] invoice(byte[] data) throws Exception {
        return sign(data, "SHA1withRSA");
    }

    static String keyAlgorithm(String jws) {
        return switch (jws) {
            case "RS256" -> "RSA";
            case "ES256" -> "EC";
            default -> throw new IllegalArgumentException(jws);
        };
    }

    void keys(String jws) throws Exception {
        // Both algorithms the mapping can return.
        KeyPairGenerator.getInstance(keyAlgorithm(jws));
        String mode = "ECB";
        Cipher.getInstance("RSA/" + mode + "/OAEPPadding");
        Cipher.getInstance(transformation);
    }
}
