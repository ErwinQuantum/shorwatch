package com.example.auth;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import io.jsonwebtoken.Jwts;

public class Vulnerable {
    Object nimbus(OctetKeyPair recipient) throws Exception {
        new OctetKeyPairGenerator(Curve.X25519).generate();
        new X25519Encrypter(recipient.toPublicJWK());
        return new JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM);
    }

    Object jjwt() {
        return Jwts.KEY.ECDH_ES_A256KW;
    }

    /** The algorithm read from its JOSE name. */
    JWEAlgorithm parsed() {
        return JWEAlgorithm.parse("ECDH-ES+A256KW");
    }
}
