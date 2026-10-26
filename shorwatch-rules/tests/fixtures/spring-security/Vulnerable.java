package com.example.config;

import java.security.interfaces.RSAPublicKey;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;
import org.springframework.security.rsa.crypto.RsaSecretEncryptor;

public class Vulnerable {
    /** Resource server verifying tokens with a pinned RSA public key. */
    JwtDecoder jwtDecoder(RSAPublicKey key) {
        return NimbusJwtDecoder.withPublicKey(key)
                .signatureAlgorithm(SignatureAlgorithm.RS512)
                .build();
    }

    /** ES256 accepted as a JWS algorithm by name. */
    String acceptedAlgorithm() {
        return JwsAlgorithms.ES256;
    }

    /** PEM-encoded RSA key read through Spring's converters. */
    Object loadKey(java.io.InputStream pem) {
        return RsaKeyConverters.x509().convert(pem);
    }

    /** spring-security-rsa: keystore-backed RSA encryption of secrets. */
    Object encryptor(Resource keystore) {
        var keys = new KeyStoreKeyFactory(keystore, "changeit".toCharArray());
        return new RsaSecretEncryptor(keys.getKeyPair("config-server"));
    }
}
