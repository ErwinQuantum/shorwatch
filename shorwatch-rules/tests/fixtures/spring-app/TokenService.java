package com.example.authserver.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
    private final KeyPair signingKeys = Jwts.SIG.ES256.keyPair().build();

    /** Injected at runtime: invisible to static analysis without data flow. */
    @Value("${tokens.audience:api}")
    private String audience;

    public record IssuedToken(String value, Instant expiresAt) {}

    public IssuedToken issue(String subject, Map<String, Object> claims) {
        Instant expiry = Instant.now().plusSeconds(900);
        String jwt = Jwts.builder()
                .subject(subject)
                .audience().add(audience).and()
                .claims(claims)
                .expiration(java.util.Date.from(expiry))
                .signWith(signingKeys.getPrivate(), Jwts.SIG.ES256)
                .compact();
        return new IssuedToken(jwt, expiry);
    }

    public Jws<Claims> verify(String token) {
        return Jwts.parser()
                .verifyWith(signingKeys.getPublic())
                .build()
                .parseSignedClaims(token);
    }
}
