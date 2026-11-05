package com.example.auth

import javax.crypto.SecretKey
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder

class Clean {
    // The algorithm comes from the caller: a choice, not a default.
    fun chosen(uri: String, algorithm: SignatureAlgorithm): JwtDecoder =
        NimbusJwtDecoder.withJwkSetUri(uri).jwsAlgorithm(algorithm).build()

    fun chosenSet(uri: String, algorithm: SignatureAlgorithm): JwtDecoder =
        NimbusJwtDecoder.withJwkSetUri(uri).jwsAlgorithms { set -> set.add(algorithm) }.build()

    // The algorithms come from the issuer's JWK Set, not from a default.
    fun byIssuer(issuer: String): JwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build()

    // The customizer takes over the key selection.
    fun customized(uri: String): JwtDecoder =
        NimbusJwtDecoder.withJwkSetUri(uri).jwtProcessorCustomizer { }.build()

    // HMAC is symmetric.
    fun shared(key: SecretKey): JwtDecoder = NimbusJwtDecoder.withSecretKey(key).build()
}
