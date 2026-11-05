package com.example.auth

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder

class Vulnerable {
    // No algorithm named: the decoder verifies RS256.
    fun byJwkSetUri(uri: String): JwtDecoder = NimbusJwtDecoder.withJwkSetUri(uri).build()

    fun bySource(source: JWKSource<SecurityContext>): JwtDecoder =
        NimbusJwtDecoder.withJwkSource(source).build()

    fun reactiveByJwkSetUri(uri: String): ReactiveJwtDecoder =
        NimbusReactiveJwtDecoder.withJwkSetUri(uri).build()

    // The choice is explicit and is what gets reported: ES256, not the default.
    fun chosen(uri: String): JwtDecoder =
        NimbusJwtDecoder.withJwkSetUri(uri).jwsAlgorithm(SignatureAlgorithm.ES256).build()
}
