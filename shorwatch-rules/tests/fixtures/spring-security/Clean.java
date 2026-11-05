package com.example.config;

import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

public class Clean {
    /** Symmetric JWT verification (HS256): not affected by Shor. */
    Object hmacDecoder(javax.crypto.SecretKey key) {
        return NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
    }

    /** `Encryptors.stronger` is AES-256-GCM; BCrypt-style password hashing is fine. */
    Object symmetric(String password, String salt) {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return Encryptors.stronger(password, salt);
    }
}
