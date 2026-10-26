# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository layout (5-crate workspace).
- `shorwatch-core`: intermediate model, rule model with validation (Shor-category rules cannot carry an auto-fix) and evaluation engine with hybrid-scheme detection.
- `shorwatch-langs`: Java frontend (tree-sitter) resolving receiver types and same-file `final` constants.
- `shorwatch-rules`: YAML loader and 11 built-in Java rules:
  - Shor category (advice only, never an auto-fix): `rsa`, `dh`, `ecdh` (including X25519/X448/XDH and ECIES), `ecdsa`, `ec` (ambiguous "EC" key material), `eddsa` (Ed25519/Ed448), `dsa`, `elgamal`.
  - Grover category: `aes-128` (with a mechanical AES-256 fix), `sha1`, `3des`.
- Hybrid-scheme detection: findings next to ML-KEM/ML-DSA/Kyber/Dilithium code, BouncyCastle PQC or liboqs imports are reported as `in_transition`. Glued hybrid names such as `X25519MLKEM768` are recognised.
- Fixture-driven snapshot tests: one folder per rule, discovered automatically.
- Static field reads (`JWSAlgorithm.RS256`, `Jwts.SIG.ES256`) as a new kind of fact, with a `field` rule pattern; single static imports are resolved for fields and unqualified method calls.
- JWT/JOSE rules: `jwt.rsa`, `jwt.ecdsa`, `jwt.eddsa`, `jwt.ecdh` and `jwt.aes-128`, covering jjwt (0.11 and 0.12), Nimbus JOSE + JWT and Auth0 java-jwt. EC JWKs are reported as generic ECC.
- Spring Security coverage: OAuth2 JOSE algorithm constants, `NimbusJwtDecoder.withPublicKey`, `RsaKeyConverters` and spring-security-rsa.
- A realistic Spring Authorization Server fixture exercising the frontend on records, lambdas, annotations and generics.
