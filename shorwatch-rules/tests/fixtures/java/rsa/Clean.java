package com.example.clean;

import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;

public class Clean {
    void run(String configured) throws Exception {
        KeyPairGenerator.getInstance("ML-KEM-768");
        Signature.getInstance("ML-DSA-65");
        Cipher.getInstance("AES/GCM/NoPadding");
        // Not a JCA receiver, so not a finding.
        new com.example.Registry().getInstance("RSA");
        // Value unknown statically: left to future data-flow analysis.
        Cipher.getInstance(configured);
        String log = "migrated away from RSA";
    }
}
