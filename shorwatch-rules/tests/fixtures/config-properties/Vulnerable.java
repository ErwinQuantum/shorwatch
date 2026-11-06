package com.example.config;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

public class Vulnerable {
    private final JwtProperties jwt;
    private final LegacyProperties legacy;
    private final TokenProperties token;

    Vulnerable(JwtProperties jwt, LegacyProperties legacy, TokenProperties token) {
        this.jwt = jwt;
        this.legacy = legacy;
        this.token = token;
    }

    void run() throws Exception {
        // app.jwt.algorithm = SHA1withRSA replaces the ECDSA default.
        Signature.getInstance(jwt.getAlgorithm());
        // Relaxed binding: app.jwt.key-type.
        KeyPairGenerator.getInstance(jwt.getKeyType());
        // Not configured: the field's default.
        MessageDigest.getInstance(legacy.getDigest());
        // A record's component is read through its accessor.
        Signature.getInstance(token.signature());
    }
}
