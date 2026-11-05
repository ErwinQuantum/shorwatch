package com.example.auth;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

public class Vulnerable {
    // No algorithm named: the decoder verifies RS256.
    JwtDecoder byJwkSetUri(String uri) {
        return NimbusJwtDecoder.withJwkSetUri(uri).build();
    }

    JwtDecoder bySource(JWKSource<SecurityContext> source) {
        return NimbusJwtDecoder.withJwkSource(source).build();
    }

    ReactiveJwtDecoder reactiveByJwkSetUri(String uri) {
        return NimbusReactiveJwtDecoder.withJwkSetUri(uri).build();
    }

    // The choice is explicit and is what gets reported: ES256, not the default.
    JwtDecoder chosen(String uri) {
        return NimbusJwtDecoder.withJwkSetUri(uri).jwsAlgorithm(SignatureAlgorithm.ES256).build();
    }
}
