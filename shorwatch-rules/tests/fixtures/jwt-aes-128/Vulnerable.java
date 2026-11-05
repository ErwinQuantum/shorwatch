package com.example.auth;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import io.jsonwebtoken.Jwts;

public class Vulnerable {
    Object nimbus() {
        return new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256);
    }

    Object jjwt() {
        Jwts.KEY.PBES2_HS256_A128KW.key();
        return Jwts.ENC.A128GCM;
    }

    /** The same algorithms read from their JOSE names. */
    Object parsed() {
        EncryptionMethod.parse("A128GCM");
        return JWEAlgorithm.parse("A128KW");
    }

    /** Two findings: ECDH (Shor) and a 128-bit key wrap (Grover). */
    Object ecdhWithShortWrap() {
        return JWEAlgorithm.ECDH_ES_A128KW;
    }
}
