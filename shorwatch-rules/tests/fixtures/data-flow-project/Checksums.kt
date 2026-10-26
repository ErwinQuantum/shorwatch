package com.example.billing.kt

import java.security.MessageDigest

/** The algorithm arrives through the constructor, from another file. */
class Checksums(private val algorithm: String) {
    fun of(data: ByteArray): ByteArray = MessageDigest.getInstance(algorithm).digest(data)
}
