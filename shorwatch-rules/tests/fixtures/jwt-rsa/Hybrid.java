package com.example.auth;

import com.nimbusds.jose.JWSAlgorithm;

/** Issuer publishing an RSA key and an ML-DSA key side by side in its JWKS. */
public class Hybrid {
    static final String PQ_ALG = "ML-DSA-65";

    Object classicalAlgorithm() {
        return JWSAlgorithm.RS256;
    }
}
