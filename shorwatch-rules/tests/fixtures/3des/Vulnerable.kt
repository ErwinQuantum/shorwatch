package com.example.legacy

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.engines.DESedeEngine

class Vulnerable {
    fun cipher(): Cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")

    fun generate(): SecretKey = KeyGenerator.getInstance(ALGORITHM).generateKey()

    fun wrap(raw: ByteArray): SecretKey = SecretKeySpec(raw, "TripleDES")

    fun lightweight(): Any = DESedeEngine()

    private companion object {
        const val ALGORITHM = "DESede"
    }
}
