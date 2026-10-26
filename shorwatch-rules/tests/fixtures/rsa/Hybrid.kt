package com.example.migrating

import java.security.KeyPairGenerator
import java.security.Signature

/** Dual signatures: RSA kept for legacy verifiers, ML-DSA added alongside. */
class Hybrid {
    fun sign(data: ByteArray): ByteArray {
        val classical = Signature.getInstance("SHA256withRSA")
        val postQuantum = Signature.getInstance("ML-DSA-65")
        return combine(classical, postQuantum, data)
    }

    private fun combine(a: Signature, b: Signature, data: ByteArray) = data
}

/** Same file, different class, no post-quantum code: still vulnerable. */
class LegacyOnly {
    fun generate(): Any = KeyPairGenerator.getInstance("RSA")
}
