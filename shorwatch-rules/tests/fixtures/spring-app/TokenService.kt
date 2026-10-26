package com.example.authserver.token

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import java.time.Instant
import java.util.Date
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service

@Service
class TokenService(
    /** Injected at runtime: invisible to static analysis without data flow. */
    @Value("\${tokens.audience:api}") private val audience: String,
) {
    private val signingKeys = Jwts.SIG.ES256.keyPair().build()

    data class IssuedToken(val value: String, val expiresAt: Instant)

    fun issue(subject: String, claims: Map<String, Any>): IssuedToken {
        val expiry = Instant.now().plusSeconds(900)
        val jwt = Jwts.builder()
            .subject(subject)
            .audience().add(audience).and()
            .claims(claims)
            .expiration(Date.from(expiry))
            .signWith(signingKeys.private, Jwts.SIG.ES256)
            .compact()
        return IssuedToken(jwt, expiry)
    }

    fun verify(token: String): Jws<Claims> =
        Jwts.parser()
            .verifyWith(signingKeys.public)
            .build()
            .parseSignedClaims(token)
}
