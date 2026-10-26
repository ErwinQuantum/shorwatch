package com.example.auth;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import io.jsonwebtoken.security.Jwks;
import java.security.interfaces.ECPublicKey;

/** EC JWKs: usable for ES256 or ECDH-ES, so reported as generic ECC. */
public class Jwk {
    Object nimbus(ECPublicKey pub) throws Exception {
        new ECKeyGenerator(Curve.P_256).generate();
        return new ECKey.Builder(Curve.P_256, pub).build();
    }

    Object jjwt() {
        return Jwks.CRV.P384.keyPair().build();
    }
}
