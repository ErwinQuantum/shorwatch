package com.example.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwks;

public class Vulnerable {
    Object nimbus(OctetKeyPair key) throws Exception {
        OctetKeyPair generated = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        new Ed25519Signer(key);
        return JWSAlgorithm.EdDSA;
    }

    Object jjwt() {
        Jwks.CRV.Ed448.keyPair().build();
        return Jwts.SIG.EdDSA;
    }
}
