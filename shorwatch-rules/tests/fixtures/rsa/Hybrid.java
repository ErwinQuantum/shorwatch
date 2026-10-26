package com.example.migrating;

import java.security.KeyPairGenerator;
import java.security.Signature;

/** Dual signatures: RSA kept for legacy verifiers, ML-DSA added alongside. */
public class Hybrid {
    byte[] sign(byte[] data) throws Exception {
        Signature classical = Signature.getInstance("SHA256withRSA");
        Signature postQuantum = Signature.getInstance("ML-DSA-65");
        return combine(classical, postQuantum, data);
    }

    private byte[] combine(Signature a, Signature b, byte[] data) {
        return data;
    }
}

/** Same file, different class, no post-quantum code: still vulnerable. */
class LegacyOnly {
    Object generate() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }
}
