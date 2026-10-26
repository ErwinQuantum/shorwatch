# Shorwatch

> Find quantum-vulnerable cryptography in your source code, and get a migration
> path to the NIST post-quantum standards.

Shorwatch is a static analyzer (SAST) written in Rust. It parses source code
into a syntax tree, matches it against declarative rules, and reports every use
of cryptography that a quantum computer would break or weaken, together with
the post-quantum replacement and the NIST standard behind it.

**Status: pre-alpha.** The detection engine and the Java rules work and are
tested; the command-line interface and SARIF output are under construction.
See [Coverage](#coverage) for exactly what is and isn't detected yet.

## Why

Most public-key cryptography in production today (RSA, Diffie-Hellman,
elliptic curves) rests on problems that **Shor's algorithm** solves efficiently
on a large enough quantum computer. That day, often called *Q-Day*, may still
be years away, but the threat is already here:

- **Harvest now, decrypt later.** Encrypted traffic recorded today can be
  stored and decrypted once the hardware exists. Data that must stay secret
  for ten years is already exposed.
- **Migrations are slow.** Moving a codebase off RSA or ECDSA changes
  protocols, key sizes and wire formats. It takes years, so inventory has to
  start now.
- **The standards are final.** NIST published
  [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) and
  [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) in 2024, and
  [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) sets the timeline to
  deprecate quantum-vulnerable algorithms.

The first step of any migration is knowing where the vulnerable crypto lives.
Shorwatch automates that inventory.

## What it detects

| Algorithm | Threat | Migrate to | Auto-fix |
|---|---|---|---|
| RSA | Shor | ML-KEM (FIPS 203) / ML-DSA (FIPS 204) | never |
| Diffie-Hellman | Shor | ML-KEM | never |
| ECDH, X25519, X448, ECIES | Shor | ML-KEM, e.g. hybrid X25519MLKEM768 | never |
| ECDSA | Shor | ML-DSA / SLH-DSA (FIPS 205) | never |
| Generic EC keys (`"EC"`) | Shor | ML-KEM or ML-DSA, depending on use | never |
| EdDSA (Ed25519, Ed448) | Shor | ML-DSA / SLH-DSA | never |
| DSA | Shor | ML-DSA | never |
| ElGamal | Shor | ML-KEM + AEAD | never |
| AES-128 | Grover | AES-256 | **yes** |
| SHA-1 | classical + Grover | SHA-256 / SHA3-256 | no |
| 3DES | Grover | AES-256-GCM | no |

The same algorithms are also detected inside **JWT/JOSE** (RS256, PS256,
ES256, EdDSA, RSA-OAEP, ECDH-ES, A128GCM, ...) with token-specific advice:
ML-DSA for JOSE, algorithm-agile verifiers and JWKS rotation.

Every finding carries the file, line, severity, an explanation, migration
advice and links to the relevant NIST documents.

### Design principles

- **Syntax tree, not grep.** Matching happens on the parsed code, so comments,
  log messages and look-alike names (`"ML-DSA"` is not DSA,
  `GCMParameterSpec(128)` is a tag length, not a key size) don't produce
  noise.
- **Hybrid-aware.** Classical crypto that sits next to post-quantum code
  (ML-KEM, ML-DSA, Kyber, Dilithium, BouncyCastle PQC, liboqs) is reported as
  **in transition** instead of vulnerable. Projects that are already migrating
  are recognized, not punished.
- **Auto-fix only where it is safe.** AES-128 → AES-256 is a parameter change,
  so Shorwatch can propose the edit. Replacing RSA or ECC changes the protocol,
  so that advice is always text for a human, never an automatic edit. The
  engine enforces this: a rule for a Shor-broken algorithm that declares a fix
  is rejected when the rules are loaded.
- **Rules are data.** Detections live in YAML files, so adding one never
  requires touching or recompiling the engine.

## Coverage

Language: **Java** (more planned).

| Covered today | Not yet |
|---|---|
| JCA / JCE: `KeyPairGenerator`, `KeyFactory`, `Cipher`, `Signature`, `KeyAgreement`, `MessageDigest`, `KeyGenerator`, `SecretKeyFactory`, key and parameter specs | Configuration files (`application.yml`, `.properties`, TLS cipher suites) |
| BouncyCastle lightweight API (engines, signers, generators) | Values injected from configuration (`@Value`) or passed through other methods (needs data-flow analysis) |
| JWT/JOSE: jjwt (0.11 and 0.12), Nimbus JOSE + JWT, Auth0 java-jwt | Algorithms chosen at runtime, e.g. from a remote JWKS |
| Spring Security: OAuth2 JOSE constants, `NimbusJwtDecoder.withPublicKey`, `RsaKeyConverters`, spring-security-rsa | Kotlin |
| Apache Commons Codec and Guava (SHA-1), `net.i2p` (EdDSA) | Compiled `.jar` dependencies |
| Algorithm names as literals, same-file `final` constants, enum/static constants and static imports | |

## Example rule

A rule is a YAML file: what to match, why it matters, and how to migrate.

```yaml
id: java.crypto.ecdsa
language: java
algorithm: ECDSA
category: shor          # shor rules can never declare a `fix`
severity: high
title: ECDSA signatures are forgeable with Shor's algorithm
suggestion: >-
  Migrate signatures to ML-DSA (FIPS 204) ...
references:
  - title: "FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)"
    url: https://csrc.nist.gov/pubs/fips/204/final
patterns:
  - call:
      type: java.security.Signature
      method: getInstance
      arg: { index: 0, matches: '(?i)^(ECD?DSA|.+with(PLAIN-|CVC-)?ECD?DSA(inP1363Format)?)$' }
  - construct:
      type: org.bouncycastle.crypto.signers.ECDSASigner
hybrid:
  markers:
    - literal: '(?i)(^|[^a-z])(kyber|dilithium|ml-?kem|ml-?dsa)'
```

All built-in rules live in [`shorwatch-rules/rules/`](shorwatch-rules/rules/).

## Architecture

A Cargo workspace with a hexagonal layout: the domain knows nothing about
parsers, files or output formats.

```
shorwatch-core     Pure domain: intermediate code model, rule model and
                   validation, evaluation engine. No I/O.
shorwatch-rules    Built-in YAML rules, loader and schema validation.
shorwatch-langs    tree-sitter frontends that lower source code into the
                   core's intermediate model (Java today).
shorwatch-report   Output adapters: SARIF 2.1.0 and terminal (in progress).
shorwatch-cli      The `shorwatch` binary (in progress).
```

Because the engine only sees a language-neutral model, the same core can later
power an editor integration (LSP), dependency scanning or CI-only incremental
scans without being rewritten.

## Usage (planned)

The CLI is under construction. The intended interface:

```sh
shorwatch scan ./my-service                    # human-readable report
shorwatch scan ./my-service --format sarif     # for GitHub code scanning
shorwatch scan . --rules ./company-rules/      # add your own YAML rules
```

SARIF output will plug into GitHub code scanning, GitLab and the VS Code SARIF
viewer.

## Building from source

Requires Rust 1.85 or later.

```sh
cargo build --release
cargo test --workspace
```

## Roadmap

- CLI, SARIF and terminal reports, CI integration
- Configuration files (`application.yml`, `.properties`)
- Data-flow analysis to follow crypto through wrapper methods
- Dependency scanning (`pom.xml`, `build.gradle`, compiled `.jar`s)
- Editor integration through LSP
- Pre-commit hook and incremental CI scans
- A post-quantum maturity score per project (migrated / hybrid / vulnerable)

## License

[Apache-2.0](LICENSE)
