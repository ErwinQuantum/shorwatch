package com.example.billing.kt

import java.security.Signature

/**
 * Not followed: a call through an interface could reach any implementation,
 * which only the compiled class hierarchy knows. No findings here, although
 * SHA1withRSA reaches Signature.getInstance at run time.
 */
class Limits {
    interface Signer {
        fun sign(data: ByteArray, algorithm: String): ByteArray
    }

    class JcaSigner : Signer {
        override fun sign(data: ByteArray, algorithm: String): ByteArray {
            val signer = Signature.getInstance(algorithm)
            signer.update(data)
            return signer.sign()
        }
    }

    fun use(signer: Signer, data: ByteArray): ByteArray = signer.sign(data, "SHA1withRSA")
}
