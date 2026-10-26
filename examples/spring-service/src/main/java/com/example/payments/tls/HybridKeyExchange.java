package com.example.payments.tls;

import javax.crypto.KEM;
import javax.crypto.KeyAgreement;

/** Already migrating: X25519 combined with ML-KEM for partner channels. */
public class HybridKeyExchange {
    KeyAgreement classicalHalf() throws Exception {
        return KeyAgreement.getInstance("X25519");
    }

    KEM postQuantumHalf() throws Exception {
        return KEM.getInstance("ML-KEM");
    }
}
