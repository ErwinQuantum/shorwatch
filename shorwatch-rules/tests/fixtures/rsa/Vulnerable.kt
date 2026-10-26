package com.example.legacy

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import javax.crypto.Cipher
import org.bouncycastle.crypto.engines.RSAEngine

class Vulnerable {
    fun generate(): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()

    fun encrypt(pair: KeyPair, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, pair.public)
        return cipher.doFinal(data)
    }

    fun sign(pair: KeyPair, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(pair.private)
            update(data)
            sign()
        }

    fun factory(): Any = KeyFactory.getInstance("rsa")

    fun lightweight(): Any = RSAEngine()

    fun commentedOut() {
        // KeyPairGenerator.getInstance("RSA")
        /* Cipher.getInstance("RSA/ECB/PKCS1Padding") */
    }

    companion object {
        private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    }
}
