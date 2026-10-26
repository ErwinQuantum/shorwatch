package com.example.clean

import java.security.KeyPairGenerator
import javax.crypto.KeyAgreement

class Clean {
    fun run() {
        // ML-KEM through the JCA (Java 24+, JEP 496).
        KeyPairGenerator.getInstance("ML-KEM")
        // Same receiver, different algorithm: owned by the ECDH rule, not this one.
        val dhLabel = "DH"
        // Partial names must not match.
        KeyPairGenerator.getInstance("DHX")
    }
}
