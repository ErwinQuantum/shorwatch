package com.example.migrating;

import java.security.Signature;

/** Composite signature: ECDSA for legacy verifiers, ML-DSA for the future. */
public class Hybrid {
    Signature[] signers() throws Exception {
        return new Signature[] {
            Signature.getInstance("SHA256withECDSA"),
            Signature.getInstance("ML-DSA-65"),
        };
    }
}
