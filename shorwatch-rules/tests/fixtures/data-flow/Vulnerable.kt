package com.example.payments

import java.security.KeyPairGenerator
import java.security.Signature
import javax.crypto.Cipher

/** Algorithms that reach the crypto API through variables, parameters and returns. */
class Vulnerable(legacy: Boolean) {
    private val transformation: String = if (legacy) "RSA/ECB/PKCS1Padding" else "AES/GCM/NoPadding"

    fun sign(data: ByteArray, algorithm: String): ByteArray {
        val signature = Signature.getInstance(algorithm)
        signature.update(data)
        return signature.sign()
    }

    /** Two findings at `getInstance`: RSA and SHA-1. */
    fun invoice(data: ByteArray): ByteArray = sign(data, "SHA1withRSA")

    fun keyAlgorithm(jws: String): String = when (jws) {
        "RS256" -> "RSA"
        "ES256" -> "EC"
        else -> throw IllegalArgumentException(jws)
    }

    fun keys(jws: String) {
        // Both algorithms the mapping can return.
        KeyPairGenerator.getInstance(keyAlgorithm(jws))
        var mode = "CBC"
        mode = "ECB"
        Cipher.getInstance("RSA/$mode/OAEPPadding")
        Cipher.getInstance(transformation)
    }
}
