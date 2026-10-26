package com.example.auth;

import com.nimbusds.jose.JWSAlgorithm;
import io.jsonwebtoken.Jwts;

public class Clean {
    Object symmetric() {
        Jwts.SIG.HS512.key().build();
        return JWSAlgorithm.HS384;
    }

    Object unknownAtCompileTime(String configured) {
        return JWSAlgorithm.parse(configured);
    }
}
