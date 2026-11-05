package com.example.keys

import java.security.KeyPairGenerator

class Vulnerable(private val kind: KeyKind) {
    // Any constant may arrive: LEGACY is RSA and SIGNING is EC.
    fun viaParameter(kind: KeyKind) {
        KeyPairGenerator.getInstance(kind.jceName)
    }

    fun viaField() {
        KeyPairGenerator.getInstance(kind.jceName)
    }

    // The constant names are the algorithm names.
    fun viaName(algorithm: Algorithm) {
        KeyPairGenerator.getInstance(algorithm.name)
    }

    fun viaToString(algorithm: Algorithm) {
        KeyPairGenerator.getInstance(algorithm.toString())
    }
}
