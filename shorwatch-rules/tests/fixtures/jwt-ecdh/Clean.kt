package com.example.auth

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import io.jsonwebtoken.Jwts

class Clean {
    /** Symmetric key wrapping with a 256-bit key: fine. */
    fun symmetric(): Any {
        Jwts.KEY.A256GCMKW.key().build()
        return listOf(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
    }
}
