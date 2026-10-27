package com.example.billing.kt

import java.security.MessageDigest

/**
 * Not followed: which overload a call picks depends on the argument types,
 * so neither is. No findings here, although SHA-1 reaches getInstance.
 */
class Limits {
    fun digest(algorithm: String) {
        MessageDigest.getInstance(algorithm)
    }

    fun digest(algorithm: StringBuilder) {
        MessageDigest.getInstance(algorithm.toString())
    }

    fun legacy() {
        digest("SHA-1")
    }
}
