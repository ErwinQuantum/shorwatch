package com.example.legacy

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.engines.DESedeEngine

class Vulnerable {
    fun cipher(): Cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")

    fun generate(): SecretKey = KeyGenerator.getInstance(ALGORITHM).generateKey()

    fun wrap(raw: ByteArray): SecretKey = SecretKeySpec(raw, "TripleDES")

    fun lightweight(): Any = DESedeEngine()

    /** Key wrapping, and password-based encryption over Triple DES. */
    fun variants() {
        Cipher.getInstance("DESedeWrap")
        Cipher.getInstance("PBEWithMD5AndTripleDES")
        SecretKeyFactory.getInstance("PBEWithSHA1AndDESede")
    }

    /** OpenSSL names write Triple DES as DES-CBC3. */
    fun openSslSuites(): Array<String> = arrayOf("DES-CBC3-SHA", "HIGH:!3DES")

    private companion object {
        const val ALGORITHM = "DESede"
    }
}
