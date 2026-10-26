package com.example.authserver.tls

import javax.crypto.KeyAgreement

/** Already migrating: hybrid post-quantum key exchange preferred for TLS. */
class HybridTlsSettings {
    /** Classical half kept for peers that don't speak ML-KEM yet. */
    fun fallbackAgreement(): KeyAgreement = KeyAgreement.getInstance("X25519")

    companion object {
        val NAMED_GROUPS = listOf("X25519MLKEM768", "x25519", "secp256r1")
    }
}
