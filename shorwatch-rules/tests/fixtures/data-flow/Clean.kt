package com.example.payments

import java.security.MessageDigest
import javax.crypto.Cipher

class Clean {
    fun digest(data: ByteArray, algorithm: String): ByteArray = MessageDigest.getInstance(algorithm).digest(data)

    fun fingerprint(data: ByteArray): ByteArray = digest(data, "SHA-256")

    fun cipher(fast: Boolean): Cipher {
        val transformation = if (fast) "ChaCha20-Poly1305" else "AES/GCM/NoPadding"
        return Cipher.getInstance(transformation)
    }
}
