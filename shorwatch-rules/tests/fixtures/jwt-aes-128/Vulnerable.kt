package com.example.auth

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import io.jsonwebtoken.Jwts

class Vulnerable {
    fun nimbus(): Any = JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256)

    fun jjwt(): Any {
        Jwts.KEY.PBES2_HS256_A128KW.key()
        return Jwts.ENC.A128GCM
    }

    /** The same algorithms read from their JOSE names. */
    fun parsed(): Any {
        EncryptionMethod.parse("A128GCM")
        return JWEAlgorithm.parse("A128KW")
    }

    /** Two findings: ECDH (Shor) and a 128-bit key wrap (Grover). */
    fun ecdhWithShortWrap(): Any = JWEAlgorithm.ECDH_ES_A128KW
}
