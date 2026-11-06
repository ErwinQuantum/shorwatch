package com.example.config

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature

class Vulnerable(
    private val jwt: JwtProperties,
    private val legacy: LegacyProperties,
    private val token: TokenProperties,
) {
    fun run() {
        // app.jwt.algorithm = SHA1withRSA replaces the ECDSA default.
        Signature.getInstance(jwt.algorithm)
        // Relaxed binding: app.jwt.key-type.
        KeyPairGenerator.getInstance(jwt.keyType)
        // Not configured: the field's default.
        MessageDigest.getInstance(legacy.digest)
        // A record's component is read through its accessor.
        Signature.getInstance(token.signature)
    }
}
