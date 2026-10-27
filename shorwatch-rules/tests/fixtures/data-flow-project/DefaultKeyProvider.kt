package com.example.billing.kt

import java.security.KeyPairGenerator

/** Reported here: the algorithm comes from Providers, through Keys.provider(). */
class DefaultKeyProvider : KeyProvider {
    override fun generator(algorithm: String): KeyPairGenerator = KeyPairGenerator.getInstance(algorithm)
}
