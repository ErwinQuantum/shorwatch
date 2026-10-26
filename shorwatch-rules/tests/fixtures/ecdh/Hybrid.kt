package com.example.migrating

import javax.crypto.KeyAgreement

/** Hybrid TLS group: X25519 secret concatenated with an ML-KEM-768 secret. */
class Hybrid {
    fun classicalHalf(): ByteArray = KeyAgreement.getInstance("X25519").generateSecret()

    companion object {
        const val GROUP = "X25519MLKEM768"
    }
}
