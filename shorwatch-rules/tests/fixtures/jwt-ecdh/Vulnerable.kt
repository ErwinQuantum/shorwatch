package com.example.auth

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import io.jsonwebtoken.Jwts

class Vulnerable {
    fun nimbus(recipient: OctetKeyPair): Any {
        OctetKeyPairGenerator(Curve.X25519).generate()
        X25519Encrypter(recipient.toPublicJWK())
        return JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
    }

    fun jjwt(): Any = Jwts.KEY.ECDH_ES_A256KW
}
