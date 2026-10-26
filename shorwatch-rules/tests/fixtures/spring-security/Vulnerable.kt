package com.example.config

import java.io.InputStream
import java.security.interfaces.RSAPublicKey
import org.springframework.core.io.Resource
import org.springframework.security.converter.RsaKeyConverters
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory
import org.springframework.security.rsa.crypto.RsaSecretEncryptor

class Vulnerable {
    /** Resource server verifying tokens with a pinned RSA public key. */
    fun jwtDecoder(key: RSAPublicKey): JwtDecoder =
        NimbusJwtDecoder.withPublicKey(key)
            .signatureAlgorithm(SignatureAlgorithm.RS512)
            .build()

    /** ES256 accepted as a JWS algorithm by name. */
    fun acceptedAlgorithm(): String = JwsAlgorithms.ES256

    /** PEM-encoded RSA key read through Spring's converters. */
    fun loadKey(pem: InputStream): Any? = RsaKeyConverters.x509().convert(pem)

    /** spring-security-rsa: keystore-backed RSA encryption of secrets. */
    fun encryptor(keystore: Resource): Any {
        val keys = KeyStoreKeyFactory(keystore, "changeit".toCharArray())
        return RsaSecretEncryptor(keys.getKeyPair("config-server"))
    }
}
