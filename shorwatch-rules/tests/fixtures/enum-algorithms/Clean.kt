package com.example.keys

import java.security.MessageDigest
import javax.crypto.Cipher

class Clean {
    enum class Safe(val jceName: String) {
        BULK("AES/GCM/NoPadding"),
        DIGEST("SHA-256"),
    }

    // Every constant of the enum is safe.
    fun cipher(safe: Safe): Cipher = Cipher.getInstance(safe.jceName)

    // A specific constant is not widened to the others: SESSION is AES.
    fun session(): Cipher = Cipher.getInstance(KeyKind.SESSION.jceName)

    // `name` of an enum with safe constants only.
    fun digest(hashes: Hashes): MessageDigest = MessageDigest.getInstance(hashes.name)

    enum class Hashes {
        SHA3_256,
        SHA_512,
    }
}
