package com.example.auth;

import javax.crypto.SecretKey;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

public class Clean {
    // The algorithm comes from the caller: a choice, not a default.
    JwtDecoder chosen(String uri, SignatureAlgorithm algorithm) {
        return NimbusJwtDecoder.withJwkSetUri(uri).jwsAlgorithm(algorithm).build();
    }

    JwtDecoder chosenSet(String uri, SignatureAlgorithm algorithm) {
        return NimbusJwtDecoder.withJwkSetUri(uri).jwsAlgorithms(set -> set.add(algorithm)).build();
    }

    // The algorithms come from the issuer's JWK Set, not from a default.
    JwtDecoder byIssuer(String issuer) {
        return NimbusJwtDecoder.withIssuerLocation(issuer).build();
    }

    // The customizer takes over the key selection.
    JwtDecoder customized(String uri) {
        return NimbusJwtDecoder.withJwkSetUri(uri).jwtProcessorCustomizer(processor -> {}).build();
    }

    // HMAC is symmetric.
    JwtDecoder shared(SecretKey key) {
        return NimbusJwtDecoder.withSecretKey(key).build();
    }
}
