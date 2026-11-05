package com.example.keys;

import java.security.KeyPairGenerator;

public class Vulnerable {
    private final KeyKind kind;

    Vulnerable(KeyKind kind) {
        this.kind = kind;
    }

    // Any constant may arrive: LEGACY is RSA and SIGNING is EC.
    void viaParameter(KeyKind kind) throws Exception {
        KeyPairGenerator.getInstance(kind.getJceName());
    }

    void viaField() throws Exception {
        KeyPairGenerator.getInstance(kind.getJceName());
    }

    // The constant names are the algorithm names.
    void viaName(Algorithm algorithm) throws Exception {
        KeyPairGenerator.getInstance(algorithm.name());
    }

    void viaToString(Algorithm algorithm) throws Exception {
        KeyPairGenerator.getInstance(algorithm.toString());
    }
}
