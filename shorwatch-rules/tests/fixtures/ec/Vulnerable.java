package com.example.legacy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class Vulnerable {
    /** Key generation alone: ECDH or ECDSA? Reported as generic ECC. */
    KeyPair generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** The signature itself is unambiguous and gets the ECDSA finding. */
    Signature signer() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }
}
