package com.example.billing.kt

import java.security.Signature

/** A call through an interface reaches its implementation. */
class Interfaces {
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
