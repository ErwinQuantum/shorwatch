package com.example.migrating

import java.security.Signature
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner

/** Composite signature: Ed25519 alongside ML-DSA. */
class Hybrid {
    fun signers(): Any = arrayOf(Signature.getInstance("Ed25519"), MLDSASigner())
}
