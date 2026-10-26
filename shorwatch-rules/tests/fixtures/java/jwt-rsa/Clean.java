package com.example.auth;

import com.auth0.jwt.algorithms.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import io.jsonwebtoken.Jwts;

public class Clean {
    Object hmac(byte[] secret) {
        // HMAC-SHA-256 is symmetric: not affected by Shor.
        Algorithm.HMAC256(secret);
        Jwts.SIG.HS256.key().build();
        return JWSAlgorithm.HS256;
    }

    /** Instance fields that merely share a name are not JOSE constants. */
    Object lookalike(Config config) {
        return config.RS256;
    }

    static class Config {
        String RS256;
    }
}
