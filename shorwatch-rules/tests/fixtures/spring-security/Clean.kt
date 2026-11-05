package com.example.config

import javax.crypto.SecretKey
import org.springframework.security.crypto.encrypt.Encryptors
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder

class Clean {
    /** Symmetric JWT verification (HS256): not affected by Shor. */
    fun hmacDecoder(key: SecretKey): Any =
        NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build()

    /** `Encryptors.stronger` is AES-256-GCM; BCrypt-style password hashing is fine. */
    fun symmetric(password: String, salt: String): Any {
        val encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
        return Encryptors.stronger(password, salt)
    }
}
