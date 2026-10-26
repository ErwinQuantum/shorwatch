package com.example.migrating

import java.security.Signature

/** Composite signature: ECDSA for legacy verifiers, ML-DSA for the future. */
class Hybrid {
    fun signers(): Array<Signature> = arrayOf(
        Signature.getInstance("SHA256withECDSA"),
        Signature.getInstance("ML-DSA-65"),
    )
}
