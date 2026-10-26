# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Docker image (`ghcr.io/erwinquantum/shorwatch`, static musl binary on Alpine) for CI systems without Rust, published for version tags; README snippets for Jenkins, Azure DevOps and GitLab CI. The static build uses mimalloc: musl's allocator halved multi-threaded scan speed.
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
  Production code only sees production config; test code also sees test config.
- `shorwatch` CLI: `scan` (parallel, `.gitignore`-aware, `--format text|sarif|json|markdown`, `--output`, `--min-severity`, `--fail-on`, `--compact`, `--rules`) and `rules`. Exit codes 0/1/2 for CI gates.
- Reports: rustc-style terminal output with the matched span underlined and a gradient banner on interactive terminals, SARIF 2.1.0 (rule descriptors, `security-severity`, fixes), JSON and Markdown.
- CycloneDX 1.6 CBOM output (`--format cbom`): one `cryptographic-asset` per algorithm with primitive, parameters and NIST quantum security level, and every occurrence as evidence. Validated against the official schema. Profiles gain a `crypto:` block, enforced by tests.
- Kotlin frontend (tree-sitter-kotlin-ng) for `.kt` and `.kts`: constructor calls without `new`, `val`/`const val`/`companion object` constants, member imports and aliases, `@Value` on constructor and function parameters, string templates, and scope functions (`apply`, `run`, `with`, `also`, `let`) passing their receiver to the lambda. All JVM rules apply unchanged; every Java fixture has a Kotlin twin that must produce the same findings.
- Receiver origin: a call on a variable created by a factory (`g = KeyGenerator.getInstance("AES"); g.init(128)`, Kotlin `...getInstance("AES").apply { init(128) }`) carries the factory's arguments, and `call` patterns can constrain them with `origin`. `KeyGenerator.init(128)` on an HMAC generator is no longer reported as AES-128; a generator of unknown origin still is.
- Rules for BouncyCastle PKIX certificate signing (`JcaContentSignerBuilder`, `Bc*ContentSignerBuilder`), XML Signature and Encryption (JSR 105 and Apache Santuario: RSA, ECDSA, DSA, EdDSA, SHA-1, AES-128, 3DES), the Android Keystore (`KeyProperties.KEY_ALGORITHM_RSA/EC`) and Nimbus algorithm families (`JWSAlgorithm.Family.RSA`...). 64 rules.
- Rules for OpenPGP (BouncyCastle `bcpg` algorithm tags), JSch (key types and `setConfig` algorithm lists, hybrid `mlkem768x25519-sha256` recognised as in transition) and Apache MINA SSHD (signature and key-exchange factories, host key algorithms). 87 rules.
- `literal` rule pattern: a string literal anywhere in the code, optionally skipped when passed to methods matching `unless_call`. Literal facts record the calls they are arguments of.
- Rules for TLS configured in code (cipher suite names in any stack, OkHttp `CipherSuite`, `jdk.tls.namedGroups`; exclusion lists ignored), cloud KMS (AWS, Azure Key Vault, Google Cloud KMS), Google Tink and OpenSAML. Spring Boot cipher lists also accept OpenSSL names. 119 rules.
- Findings know whether they are in production or test code (`CodeRole`, set from the project layout: Maven/Gradle test source sets, test directories, `*Test`/`*IT` classes). Every format shows it (terminal label and summary split, `role` in JSON and SARIF plus a `test` SARIF tag, Markdown, CBOM), and `--exclude-tests` skips test code.
- `examples/`: one file per algorithm, a Spring Boot service (Java and Kotlin) and its reports in every format.
- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

- Data flow within a file: an algorithm reaching the crypto API through a variable, a field, a parameter fed by a call in the same file, a method's return value, a concatenation or a conditional is resolved, and the finding carries its path (`flow`: where the value is written, then each assignment, call or return). Shown in the terminal, as SARIF `codeFlows`, in JSON and in Markdown. On the field-test projects: 9 new findings, all true positives.

- `--format html`: a self-contained HTML report (styles, script and data embedded, nothing loaded from the network) with a summary, post-quantum readiness, findings by severity and algorithm, filters, and every finding with its code, explanation, advice and data-flow path. Light and dark themes, print styles.
- The example Spring service gains a statement signer whose algorithm comes from a `switch`, to show data flow; `examples/output/` includes the HTML report.

- Data flow across files: an algorithm passed to a method or constructor of another file, or returned by one, is followed through the project (receiver type, name and arity; up to three calls), and each step of the path names its file. A method's return binds its parameters to the call's own arguments. Production code takes no values from test code. On the field-test projects this finds Keycloak's central signing contexts (RSA, ECDSA, EdDSA through `JavaAlgorithm.getJavaAlgorithm`) and Spring Security's SHA-1 password encoder across three files; all new findings were true positives.

### Fixed
- Absolute paths outside the working directory were shown as `C:/\/Users/...` on Windows.

### Changed
- A type name without an import only matches types of the file's package, its on-demand imports and the implicit ones (`java.lang`, Kotlin's defaults); Java 25 `import module` keeps any match. Fixes same-package classes mistaken for library types (Keycloak's `KeyType` for Azure's).
- The Spring Security RSA rule also covers `org.springframework.security.crypto.encrypt`, where Spring Security 6.3 moved spring-security-rsa.
- Rules target a platform (`jvm`, `config`) instead of a language, so JVM rules apply to Java and Kotlin alike.
- JVM name resolution (receivers, constants, injected values, member imports) is shared by the Java and Kotlin frontends (`shorwatch-langs/src/jvm`).
- MSRV raised to Rust 1.88.
- Rules are split into algorithm profiles (`rules/algorithms/`, written once) and per-library rule files (`rules/jvm/<library>/`, `rules/config/<framework>/`) holding only patterns. Rule ids follow the path, e.g. `jvm.nimbus.jose-rsa`. Hybrid markers are shared (`rules/markers/pqc.yaml`). Every file under `rules/` is embedded automatically.
