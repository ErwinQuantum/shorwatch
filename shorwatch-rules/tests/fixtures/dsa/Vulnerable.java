package com.example.legacy;

import java.security.KeyPairGenerator;
import java.security.Signature;
import org.bouncycastle.crypto.signers.DSASigner;

public class Vulnerable {
    Object generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    Signature signer() throws Exception {
        return Signature.getInstance("SHA256withDSA");
    }

    Object bouncyCastle() {
        return new DSASigner();
    }

    // Older names the JDK still accepts for the same signature.
    void legacyNames() throws Exception {
        Signature.getInstance("DSS");
        Signature.getInstance("DSAWithSHA1");
        Signature.getInstance("RawDSA");
        Signature.getInstance("1.2.840.10040.4.3");
    }
}
