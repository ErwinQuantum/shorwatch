package com.example.billing.kt

import java.security.KeyPairGenerator

/** A pluggable crypto provider, as frameworks have them. */
interface KeyProvider {
    fun generator(algorithm: String): KeyPairGenerator
}
