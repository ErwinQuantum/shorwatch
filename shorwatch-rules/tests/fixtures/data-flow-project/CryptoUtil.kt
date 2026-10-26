package com.example.billing.kt

import java.security.Signature
import javax.crypto.Cipher

/** A shared helper: the algorithms come from its callers in other files. */
class CryptoUtil {
    fun cipher(transformation: String): Cipher = Cipher.getInstance(transformation)

    companion object {
        fun sign(data: ByteArray, algorithm: String): ByteArray {
            val signer = Signature.getInstance(algorithm)
            signer.update(data)
            return signer.sign()
        }
    }
}
