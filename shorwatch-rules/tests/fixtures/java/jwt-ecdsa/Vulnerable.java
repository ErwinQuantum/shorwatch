package com.example.auth;

import com.auth0.jwt.algorithms.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import io.jsonwebtoken.Jwts;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class Vulnerable {
    Object nimbus(ECKey key) throws Exception {
        new ECDSAVerifier(key);
        return JWSAlgorithm.ES256K;
    }

    Object jjwt() {
        return Jwts.SIG.ES384.keyPair().build();
    }

    Object auth0(ECPublicKey pub, ECPrivateKey priv) {
        return Algorithm.ECDSA256(pub, priv);
    }

    Object parsed() {
        return JWSAlgorithm.parse("ES512");
    }
}
