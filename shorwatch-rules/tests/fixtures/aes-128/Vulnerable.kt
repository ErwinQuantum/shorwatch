package com.example.legacy

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class Vulnerable {
    fun literal(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(128)
        return generator.generateKey()
    }

    fun pinnedTransformation(): Cipher = Cipher.getInstance("AES_128/GCM/NoPadding")

    /** Found, but no fix: the edit belongs on the constant, not here. */
    fun viaConstant(): SecretKey =
        KeyGenerator.getInstance("AES").apply { init(KEY_BITS) }.generateKey()

    /** Found, but no fix: the literal is not written as plain `128`. */
    fun hex(random: SecureRandom): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(0x80, random)
        return generator.generateKey()
    }

    companion object {
        private const val KEY_BITS = 128
    }
}
