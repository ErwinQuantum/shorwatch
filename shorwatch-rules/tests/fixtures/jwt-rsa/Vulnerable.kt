package com.example.auth

import com.auth0.jwt.algorithms.Algorithm.RSA256
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class Vulnerable {
    /** Nimbus: header algorithm, signer and key generation. */
    fun nimbus(key: RSAPrivateKey): Any {
        val header = JWSHeader(JWSAlgorithm.RS256)
        RSASSASigner(key)
        return RSAKeyGenerator(2048).generate()
    }

    /** Nimbus JWK built from an existing key pair, as in Spring Boot samples. */
    fun jwk(pub: RSAPublicKey, priv: RSAPrivateKey): Any = RSAKey.Builder(pub).privateKey(priv).build()

    /** Nimbus JWE with RSA-OAEP-256 key encryption. */
    fun encryptedHeader(): Any = JWEAlgorithm.RSA_OAEP_256

    /** The same algorithm read from its JOSE name. */
    fun parsedHeader(): JWEAlgorithm = JWEAlgorithm.parse("RSA-OAEP-256")

    /** jjwt 0.12: key pair and signature in one idiom. */
    fun jjwt(): String {
        val pair: KeyPair = Jwts.SIG.PS256.keyPair().build()
        return Jwts.builder().subject("alice").signWith(pair.private).compact()
    }

    /** jjwt 0.11 legacy enum. */
    fun legacyJjwt(): Any = SignatureAlgorithm.RS512

    /** Auth0 java-jwt, member import. */
    fun auth0(pub: RSAPublicKey, priv: RSAPrivateKey): Any = RSA256(pub, priv)
}
