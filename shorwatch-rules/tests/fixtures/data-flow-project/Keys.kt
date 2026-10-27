package com.example.billing.kt

object Keys {
    private val provider: KeyProvider = DefaultKeyProvider()

    fun provider(): KeyProvider = provider
}
