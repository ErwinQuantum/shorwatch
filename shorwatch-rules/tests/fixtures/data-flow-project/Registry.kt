package com.example.billing.kt

/** Two calls away from the provider: Registry.registry().provider(). */
class Registry {
    fun provider(): KeyProvider = Keys.provider()

    companion object {
        fun registry(): Registry = Registry()
    }
}
