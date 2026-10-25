package com.example.migrating;

import java.security.Signature;

public class Hybrid {
    /** Verifies old DSA signatures; new ones are produced with Dilithium. */
    Signature[] verifiers() throws Exception {
        return new Signature[] {
            Signature.getInstance("SHA256withDSA"),
            Signature.getInstance("Dilithium3"),
        };
    }
}
