package com.example.migrating;

import javax.crypto.KeyAgreement;

/** Hybrid TLS group: X25519 secret concatenated with an ML-KEM-768 secret. */
public class Hybrid {
    static final String GROUP = "X25519MLKEM768";

    byte[] classicalHalf() throws Exception {
        return KeyAgreement.getInstance("X25519").generateSecret();
    }
}
