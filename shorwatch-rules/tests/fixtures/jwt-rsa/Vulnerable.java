package com.example.auth;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Vulnerable {
    /** Nimbus: header algorithm, signer and key generation. */
    Object nimbus(RSAPrivateKey key) throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
        new RSASSASigner(key);
        return new RSAKeyGenerator(2048).generate();
    }

    /** Nimbus JWK built from an existing key pair, as in Spring Boot samples. */
    Object jwk(RSAPublicKey pub, RSAPrivateKey priv) {
        return new RSAKey.Builder(pub).privateKey(priv).build();
    }

    /** Nimbus JWE with RSA-OAEP-256 key encryption. */
    Object encryptedHeader() {
        return JWEAlgorithm.RSA_OAEP_256;
    }

    /** The same algorithm read from its JOSE name. */
    JWEAlgorithm parsedHeader() {
        return JWEAlgorithm.parse("RSA-OAEP-256");
    }

    /** jjwt 0.12: key pair and signature in one idiom. */
    String jjwt() {
        KeyPair pair = Jwts.SIG.PS256.keyPair().build();
        return Jwts.builder().subject("alice").signWith(pair.getPrivate()).compact();
    }

    /** jjwt 0.11 legacy enum. */
    Object legacyJjwt() {
        return SignatureAlgorithm.RS512;
    }

    /** Auth0 java-jwt, statically imported. */
    Object auth0(RSAPublicKey pub, RSAPrivateKey priv) {
        return RSA256(pub, priv);
    }
}
