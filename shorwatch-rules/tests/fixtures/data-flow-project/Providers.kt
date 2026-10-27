package com.example.billing.kt

import java.security.KeyPair
import java.security.KeyPairGenerator

class Providers {
    /** A chained call: provider() returns the interface. */
    fun partnerKeys(): KeyPair = Keys.provider().generator("RSA").generateKeyPair()

    /** A constant of another file, used here and passed to the provider. */
    fun agreementKeys(): KeyPair {
        KeyPairGenerator.getInstance(KeyTypes.EC)
        return Keys.provider().generator(KeyTypes.EC).generateKeyPair()
    }
}
