package com.example.auth

import com.auth0.jwt.algorithms.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import io.jsonwebtoken.Jwts

class Clean {
    fun hmac(secret: ByteArray): Any {
        // HMAC-SHA-256 is symmetric: not affected by Shor.
        Algorithm.HMAC256(secret)
        Jwts.SIG.HS256.key().build()
        return JWSAlgorithm.HS256
    }

    /** Properties that merely share a name are not JOSE constants. */
    fun lookalike(config: Config): Any? = config.RS256

    class Config {
        var RS256: String? = null
    }
}
