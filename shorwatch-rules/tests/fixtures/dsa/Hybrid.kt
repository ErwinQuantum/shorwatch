package com.example.migrating

import java.security.Signature

class Hybrid {
    /** Verifies old DSA signatures; new ones are produced with Dilithium. */
    fun verifiers(): List<Signature> = listOf(
        Signature.getInstance("SHA256withDSA"),
        Signature.getInstance("Dilithium3"),
    )
}
