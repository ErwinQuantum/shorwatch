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
- Configuration frontends: YAML (tree-sitter-yaml) and `.properties`, flattening keys the Spring way (`a.b[0].c`), with a `property` rule pattern.
- Config rules: Spring Boot resource server algorithms and public keys, TLS cipher suites (`*.ssl.ciphers`), Spring Cloud Config encryption keys, and application keys such as `jwt.algorithm: RS256`. New `tls-key-exchange` profile.
- Values injected with `@Value("${key:default}")` are resolved across files (`shorwatch_core::link`) against every profile's config, with Spring relaxed binding.
- `shorwatch` CLI: `scan` (parallel, `.gitignore`-aware, `--format text|sarif|json|markdown`, `--output`, `--min-severity`, `--fail-on`, `--compact`, `--rules`) and `rules`. Exit codes 0/1/2 for CI gates.
- Reports: rustc-style terminal output with the matched span underlined and a gradient banner on interactive terminals, SARIF 2.1.0 (rule descriptors, `security-severity`, fixes), JSON and Markdown.
- CycloneDX 1.6 CBOM output (`--format cbom`): one `cryptographic-asset` per algorithm with primitive, parameters and NIST quantum security level, and every occurrence as evidence. Validated against the official schema. Profiles gain a `crypto:` block, enforced by tests.
- Kotlin frontend (tree-sitter-kotlin-ng) for `.kt` and `.kts`: constructor calls without `new`, `val`/`const val`/`companion object` constants, member imports and aliases, `@Value` on constructor and function parameters, string templates, and scope functions (`apply`, `run`, `with`, `also`, `let`) passing their receiver to the lambda. All JVM rules apply unchanged; every Java fixture has a Kotlin twin that must produce the same findings.
- Receiver origin: a call on a variable created by a factory (`g = KeyGenerator.getInstance("AES"); g.init(128)`, Kotlin `...getInstance("AES").apply { init(128) }`) carries the factory's arguments, and `call` patterns can constrain them with `origin`. `KeyGenerator.init(128)` on an HMAC generator is no longer reported as AES-128; a generator of unknown origin still is.
- `examples/`: one file per algorithm, a Spring Boot service (Java and Kotlin) and its reports in every format.
- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

### Changed
- Rules target a platform (`jvm`, `config`) instead of a language, so JVM rules apply to Java and Kotlin alike.
- JVM name resolution (receivers, constants, injected values, member imports) is shared by the Java and Kotlin frontends (`shorwatch-langs/src/jvm`).
- MSRV raised to Rust 1.88.
- Rules are split into algorithm profiles (`rules/algorithms/`, written once) and per-library rule files (`rules/jvm/<library>/`, `rules/config/<framework>/`) holding only patterns. Rule ids follow the path, e.g. `jvm.nimbus.jose-rsa`. Hybrid markers are shared (`rules/markers/pqc.yaml`). Every file under `rules/` is embedded automatically.
