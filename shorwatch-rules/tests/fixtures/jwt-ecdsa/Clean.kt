package com.example.auth

import com.nimbusds.jose.JWSAlgorithm
import io.jsonwebtoken.Jwts

class Clean {
    fun symmetric(): Any {
        Jwts.SIG.HS512.key().build()
        return JWSAlgorithm.HS384
    }

    fun unknownAtCompileTime(configured: String): Any = JWSAlgorithm.parse(configured)
}
