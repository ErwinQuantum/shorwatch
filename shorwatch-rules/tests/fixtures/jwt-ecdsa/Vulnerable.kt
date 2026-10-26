package com.example.auth

import com.auth0.jwt.algorithms.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import io.jsonwebtoken.Jwts
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

class Vulnerable {
    fun nimbus(key: ECKey): Any {
        ECDSAVerifier(key)
        return JWSAlgorithm.ES256K
    }

    fun jjwt(): Any = Jwts.SIG.ES384.keyPair().build()

    fun auth0(pub: ECPublicKey, priv: ECPrivateKey): Any = Algorithm.ECDSA256(pub, priv)

    fun parsed(): Any = JWSAlgorithm.parse("ES512")
}
