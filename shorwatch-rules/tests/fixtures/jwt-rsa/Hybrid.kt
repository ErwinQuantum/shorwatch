package com.example.auth

import com.nimbusds.jose.JWSAlgorithm

/** Issuer publishing an RSA key and an ML-DSA key side by side in its JWKS. */
class Hybrid {
    fun classicalAlgorithm(): Any = JWSAlgorithm.RS256

    companion object {
        const val PQ_ALG = "ML-DSA-65"
    }
}
