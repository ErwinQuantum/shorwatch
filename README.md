# Shorwatch

> Find quantum-vulnerable cryptography in your source code, and get a migration
> path to the NIST post-quantum standards.

Shorwatch is a static analyzer (SAST) written in Rust. It parses source code
into a syntax tree, matches it against declarative rules, and reports every use
of cryptography that a quantum computer would break or weaken, together with
the post-quantum replacement and the NIST standard behind it.

**Status: pre-alpha (v0.1 in progress).** The scanner works end to end on Java,
Kotlin and Spring projects; no release has been published yet. See
[Coverage](#coverage) for exactly what is and isn't detected.

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

## Usage

```sh
cargo install --path shorwatch-cli          # until the first release is published

shorwatch scan .                             # scan the current project
shorwatch scan src/ config/ --compact        # several paths, one line per finding
shorwatch scan . --format sarif -o shorwatch.sarif
shorwatch scan . --format cbom -o crypto.cdx.json # CycloneDX CBOM inventory
shorwatch scan . --min-severity medium --fail-on any
shorwatch scan . --rules ./company-rules/    # add your own YAML rules
shorwatch rules                              # list the rules in effect
```

`scan` walks the given paths respecting `.gitignore`, analyzes `.java`,
`.kt`, `.kts`, `.yml`, `.yaml` and `.properties` files in parallel, and resolves
`@Value("${...}")` injections against the project's configuration files.

| Option | |
|---|---|
| `--format text\|sarif\|cbom\|json\|markdown` | Output format (default `text`, coloured on terminals) |
| `-o, --output FILE` | Write the report to a file |
| `--min-severity info\|low\|medium\|high\|critical` | Hide less severe findings |
| `--fail-on vulnerable\|any\|never` | When to exit with code 1 (default: any finding still `vulnerable`) |
| `--exclude-tests` | Skip test code (Maven/Gradle test source sets such as `src/test` or `src/jvmTest`, test directories, `*Test`/`*IT` classes). Without it, findings in test code are reported and labelled as such |
| `--compact` | One line per finding |
| `--rules DIR` | Extra rules directory (repeatable) |

Exit codes: `0` nothing failing, `1` failing findings, `2` error.

### Example output

Scanning [`examples/spring-service`](examples/spring-service/), a small Spring
Boot service:

```text
 HIGH  RSA · jvm.jca.rsa · vulnerable
  ──▶ examples/spring-service/src/main/java/com/example/payments/auth/AuthorizationServerConfig.java:32:42
   │
32 │             KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
   │                                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   │ RSA is broken by Shor's algorithm
   = help: Plan a protocol migration, not a drop-in swap. For key establishment and
           encryption, move to ML-KEM (FIPS 203); for signatures, move to ML-DSA (FIPS
           204). During the transition, a hybrid scheme (e.g. X25519+ML-KEM, or
           RSA/ECDSA dual signatures with ML-DSA) keeps classical security while adding
           post-quantum protection.
   = ref: https://csrc.nist.gov/pubs/fips/203/final

 HIGH  ECDH · jvm.jca.ecdh · in transition
  ──▶ examples/spring-service/src/main/java/com/example/payments/tls/HybridKeyExchange.java:9:16
   │
 9 │         return KeyAgreement.getInstance("X25519");
   │                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   │ Elliptic-curve Diffie-Hellman (including X25519/X448) is broken by Shor's algorithm
   = in transition: post-quantum code at line 13 (ML-KEM)
   ...

 HIGH  ECC · jvm.jca.ec · vulnerable
  ──▶ examples/spring-service/src/main/kotlin/com/example/payments/partners/PartnerKeys.kt:19:9
   │
19 │         KeyPairGenerator.getInstance("EC").apply {
   │         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   │ Elliptic-curve keys are broken by Shor's algorithm
   ...

 Summary  13 findings in 7 files (7 scanned)
          12 vulnerable · 1 in transition · 1 auto-fixable
          10 high · 2 medium · 1 low
```

Every format for that scan is in [`examples/output/`](examples/output/):
[text](examples/output/report.txt), [SARIF](examples/output/report.sarif),
[CBOM](examples/output/report.cdx.json), [JSON](examples/output/report.json),
[Markdown](examples/output/report.md).

### Cryptography Bill of Materials (CBOM)

`--format cbom` emits a [CycloneDX 1.6](https://cyclonedx.org/capabilities/cbom/)
CBOM, the inventory format used by the post-quantum ecosystem (PQCA tooling
such as CBOMkit). Each algorithm becomes a `cryptographic-asset` with its
primitive, parameters and **NIST quantum security level**, and every place it
occurs is listed as evidence:

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto/algorithm/aes-128",
  "name": "AES-128",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "block-cipher",
      "parameterSetIdentifier": "128",
      "cryptoFunctions": ["keygen", "encrypt", "decrypt"],
      "classicalSecurityLevel": 128,
      "nistQuantumSecurityLevel": 1
    }
  },
  "evidence": {
    "occurrences": [
      {
        "location": "examples/spring-service/src/main/java/com/example/payments/crypto/LegacyCrypto.java",
        "line": 22,
        "additionalContext": "jvm.jca.aes-128 (vulnerable)"
      }
    ]
  }
}
```

SARIF answers *what must be fixed and where*; the CBOM answers *what
cryptography the system contains*. The CBOM is validated against the official
CycloneDX 1.6 schema and is deterministic (no timestamp or random serial
number). Today it inventories the quantum-vulnerable algorithms Shorwatch
detects; quantum-safe algorithms are not listed yet.

### GitHub code scanning

SARIF results show up as alerts on the exact line of a pull request:

```yaml
# .github/workflows/shorwatch.yml
name: Shorwatch
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/ErwinQuantum/shorwatch shorwatch-cli
      - run: shorwatch scan . --format sarif -o shorwatch.sarif --fail-on never
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shorwatch.sarif
```

### Docker (Jenkins, Azure DevOps, GitLab CI)

The image needs no Rust toolchain: a static binary on Alpine (~23 MB).

```sh
docker run --rm -v "$PWD:/src" ghcr.io/erwinquantum/shorwatch scan . --format sarif -o shorwatch.sarif
```

Jenkins, with the [Warnings Next Generation](https://plugins.jenkins.io/warnings-ng/)
plugin reading the SARIF report:

```groovy
stage('Post-quantum crypto') {
    steps {
        sh 'docker run --rm -v "$WORKSPACE:/src" ghcr.io/erwinquantum/shorwatch scan . --format sarif -o shorwatch.sarif --fail-on never'
        recordIssues tool: sarif(pattern: 'shorwatch.sarif', id: 'shorwatch', name: 'Shorwatch')
    }
}
```

Azure DevOps, with the [SARIF SAST Scans Tab](https://marketplace.visualstudio.com/items?itemName=sariftools.scans)
extension (it reads the `CodeAnalysisLogs` artifact):

```yaml
- script: |
    docker run --rm -v "$(Build.SourcesDirectory):/src" ghcr.io/erwinquantum/shorwatch \
      scan . --format sarif -o shorwatch.sarif --fail-on never
- publish: shorwatch.sarif
  artifact: CodeAnalysisLogs
```

GitLab CI:

```yaml
shorwatch:
  image:
    name: ghcr.io/erwinquantum/shorwatch
    entrypoint: [""]
  script:
    - shorwatch scan . --format markdown -o shorwatch.md
  artifacts:
    paths: [shorwatch.md]
```

## Coverage

Java and Kotlin source code and its configuration (`application.yml`,
`.properties`). Rules are written per platform, not per language: one JVM rule
covers both, and every Java test fixture has a Kotlin twin that must produce
the same findings.

| Covered today | Not yet |
|---|---|
| JCA / JCE: `KeyPairGenerator`, `KeyFactory`, `Cipher`, `Signature`, `KeyAgreement`, `MessageDigest`, `KeyGenerator`, `SecretKeyFactory`, key and parameter specs | Groovy and Scala |
| BouncyCastle lightweight API (engines, signers, generators) and PKIX certificate signing (`JcaContentSignerBuilder`) | `@ConfigurationProperties` binding; values passed through other methods (needs data-flow analysis) |
| JWT/JOSE: jjwt (0.11 and 0.12), Nimbus JOSE + JWT, Auth0 java-jwt | Algorithms chosen at runtime, e.g. from a remote JWKS |
| Spring Security: OAuth2 JOSE constants, `NimbusJwtDecoder.withPublicKey`, `RsaKeyConverters`, spring-security-rsa | Quarkus and Micronaut configuration keys |
| Spring Boot config: `jws-algorithms`, `public-key-location`, TLS cipher suites (`*.ssl.ciphers`); Spring Cloud Config encryption keys; app keys like `jwt.algorithm: RS256` | Compiled `.jar` dependencies |
| Values injected with `@Value("${key:default}")`, resolved against every profile's config file | |
| Apache Commons Codec and Guava (SHA-1), `net.i2p` (EdDSA) | |
| OpenPGP (BouncyCastle `bcpg`): key, hash and symmetric algorithm tags | The algorithm of keys read from existing key rings |
| SSH: JSch key types and `setConfig` algorithm lists, Apache MINA SSHD signature and key-exchange factories, host key algorithms | Library defaults when nothing is configured |
| XML Signature and Encryption (SAML, WS-Security): JSR 105 `SignatureMethod`/`DigestMethod`, Apache Santuario | Algorithm URIs written as strings |
| Android Keystore (`KeyProperties.KEY_ALGORITHM_RSA/EC`) | |
| Algorithm names as literals, same-file `final` constants, enum/static constants and static imports | |
| Kotlin idioms: constructor calls without `new`, `val` / `const val` / `companion object` constants, member imports, `@Value` on constructor parameters, scope functions (`apply`, `run`, `with`, `also`, `let`) | Kotlin extension functions that wrap crypto (needs data flow) |

## Rules

Rules are YAML data, organized so that adding coverage means adding a file:

```
shorwatch-rules/rules/
  algorithms/   what each algorithm is and why it matters (written once)
  markers/      signs of post-quantum code, for hybrid detection
  jvm/          one folder per library: jca, bouncycastle, nimbus, jjwt,
                auth0, spring-security, ...
  config/       one folder per framework: spring-boot, spring-cloud-config, app
```

An algorithm profile carries the explanation, migration advice and NIST
references:

```yaml
# algorithms/ecdsa.yaml
algorithm: ECDSA
category: shor          # rules for Shor-broken algorithms can never declare a `fix`
severity: high
title: ECDSA signatures are forgeable with Shor's algorithm
suggestion: >-
  Migrate signatures to ML-DSA (FIPS 204) ...
references:
  - title: "FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)"
    url: https://csrc.nist.gov/pubs/fips/204/final
hybrid: pqc
```

A library rule only says what to match:

```yaml
# jvm/bouncycastle/ecdsa.yaml
id: jvm.bouncycastle.ecdsa
profile: ecdsa
platform: jvm
patterns:
  - construct:
      type: org.bouncycastle.crypto.signers.ECDSASigner
```

```yaml
# config/spring-boot/jose-rsa.yaml
id: config.spring-boot.jose-rsa
profile: jose-rsa
platform: config
patterns:
  - property:
      key: '(?i)^spring\.security\.oauth2\.resourceserver\.jwt\.jws-?algorithms?(\[\d+\])?$'
      matches: '(?i)(^|[,\s])(RS|PS)(256|384|512)($|[,\s])'
```

## Architecture

A Cargo workspace with a hexagonal layout: the domain knows nothing about
parsers, files or output formats.

```
shorwatch-core     Pure domain: intermediate code model, rule model and
                   validation, evaluation engine, cross-file linking. No I/O.
shorwatch-rules    Built-in YAML rules, loader and schema validation.
shorwatch-langs    Frontends that lower files into the core's intermediate
                   model: Java and Kotlin (tree-sitter, sharing one JVM
                   name resolver), YAML (tree-sitter), .properties.
shorwatch-report   Output adapters: terminal, SARIF 2.1.0, CycloneDX CBOM,
                   JSON and Markdown.
shorwatch-cli      The `shorwatch` binary.
```

Because the engine only sees a language-neutral model, the same core can later
power an editor integration (LSP), dependency scanning or CI-only incremental
scans without being rewritten.

## Building from source

Requires Rust 1.88 or later.

```sh
cargo build --release
cargo test --workspace
```

## Roadmap

- More configuration formats (Quarkus, Micronaut)
- Data-flow analysis to follow crypto through wrapper methods
- Dependency scanning (`pom.xml`, `build.gradle`, compiled `.jar`s)
- Editor integration through LSP
- Pre-commit hook and incremental CI scans
- A post-quantum maturity score per project (migrated / hybrid / vulnerable)

## License

[Apache-2.0](LICENSE)
