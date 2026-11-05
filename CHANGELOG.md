# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The cryptographic libraries a project declares in its build files: Maven
  `pom.xml`, Gradle `build.gradle` and `build.gradle.kts` (Groovy and Kotlin
  DSL) and `libs.versions.toml`, found by file name. About 20 known libraries
  (BouncyCastle, Nimbus, jjwt, JSch, Tink, the cloud KMS clients...) are
  listed with their version and, where the catalog knows it, whether that
  version can do post-quantum cryptography (BouncyCastle from 1.79).
- They are an inventory, not findings: the summary counts them, the JSON
  report lists `dependencies`, the Markdown and HTML reports have a section,
  and the CBOM carries them as `library` components with a package URL. They
  feed no gate, baseline or SARIF result.
- The catalog of known libraries is data (`rules/libraries/<id>.yaml`), and
  `--rules` directories may add their own.
- `docs/algorithms/`: one page per algorithm Shorwatch flags (RSA, ECDSA,
  AES-128, SHA-1, the JOSE variants...) explaining why it is a problem, how
  urgent it is and what to do, plus an introduction to Shor, Grover and
  harvest-now-decrypt-later. Every finding's references now start with a link
  to its page, and a test keeps profiles and pages in step.
- Five rules for places that were not read: Jasypt's
  `jasypt.encryptor.algorithm` over Triple DES, AWS KMS `DataKeySpec.AES_128`,
  Spring Security's SHA-1 password encoders (`MessageDigestPasswordEncoder`,
  `LdapShaPasswordEncoder`), and application-defined JWE settings (`alg` and
  `enc` keys naming ECDH-ES or a 128-bit AES algorithm).

### Changed

- The same algorithm is now recognised under more of the names code uses, so a
  scan can report more findings than 0.1.0 on the same code:
  - Names the JDK accepts as aliases or OIDs for signatures and digests
    (`DSAWithSHA1`, `SHA1/DSA`, `DSS`, `1.2.840.10045.4.3.2`...).
  - OpenSSL cipher names next to the IANA ones, including static RSA suites
    that carry no key-exchange prefix (`AES256-SHA`, `AES128-GCM-SHA256`,
    `DES-CBC3-SHA`) and `ECDH-RSA-...`.
  - JOSE names read from text (`JWEAlgorithm.parse("ECDH-ES")`,
    `EncryptionMethod.parse("A128GCM")`).
  - Kafka's `ssl.cipher.suites`, Commons Codec's deprecated `shaHex` family
    and `DESedeWrap` / password-based Triple DES names.
  - Every name the JDK 21 providers register: the OIDs of RSA, DSA and ECDSA
    signatures (including the SHA-3 ones), `PSS`, `EllipticCurve`, the key and
    X25519/X448/Ed25519/Ed448 OIDs, `AlgorithmParameters` for RSASSA-PSS, DSA,
    DH, EC and Triple DES, `KEM.getInstance("DHKEM")`, `AESWrap_128`, and plain
    `DSA` / `DSS` / `MD5andSHA1withRSA`, which also use SHA-1. A test calls all
    632 names the JDK accepts and checks what each produces.
  - Every name BouncyCastle 1.85 registers through the JCA: `MD5withRSAEncryption`,
    `RSAPSS`, `SHA256/ECDSA`, `DETECDSA`, `ECNR`, `ECCDHU`, `X25519UwithSHA256KDF`,
    `PBEWITHSHAAND3-KEYTRIPLEDES-CBC`, `TDEA`, the OIDs of ECDSA over BSI curves,
    and ElGamal and ECIES parameters. The post-quantum and composite names are
    not reported as classical algorithms. A test covers 4,175 names.
  - Smaller additions: ElGamal parameter generators and BouncyCastle specs,
    BouncyCastle's `RSADigestSigner` and unified-model ECDH, and XML Signature
    algorithms written as URIs.
- RS256 used as a default is now reported: `NimbusJwtDecoder.withJwkSetUri(...)`
  and `withJwkSource(...)` (plain and reactive) when the chain names no
  algorithm, and Spring Boot's `jwk-set-uri` when no `jws-algorithms` is set.
  Rules can say this with two new conditions, `unless_chain` (a method called
  later in the same chain) and `unless_property` (another key in the same file).
- A rule now reports a line once: a second match of the same rule on the same
  line (a cipher suite written under its IANA and OpenSSL names, two algorithm
  names in one expression) is no longer a second finding. The baseline already
  treated them as one. Scans can therefore report fewer findings than before.
- Reference links in findings start with the Shorwatch page for the algorithm.
  The reports in `examples/output` were regenerated for that.

### Security

- Build files are read as untrusted input: XML external entities are never
  read, nesting and resolved coordinates are bounded, and the readers are
  linear in the file.

## [0.1.0] - 2026-10-30

The first release.

### Detection

- 127 rules over 17 algorithm profiles: RSA, Diffie-Hellman, ECDH (X25519,
  X448, ECIES), ECDSA, generic EC keys, EdDSA, DSA and ElGamal (broken by
  Shor's algorithm); AES-128, SHA-1 and 3DES (weakened by Grover's); the same
  algorithms in JWT/JOSE, and TLS key exchange.
- Java and Kotlin sources: JCA/JCE, BouncyCastle (lightweight API, PKIX,
  OpenPGP), Nimbus JOSE + JWT, jjwt, Auth0 java-jwt, Spring Security, JSch,
  Apache MINA SSHD, XML Signature and Encryption (JSR 105, Santuario,
  OpenSAML), TLS in code (JSSE, Netty, Jetty, Tomcat, OkHttp), AWS, Azure and
  Google Cloud KMS, Google Tink, the Android Keystore, Commons Codec, Guava.
- Spring configuration (`application.yml`, `.properties`): resource server
  algorithms and keys, TLS cipher suites, Spring Cloud Config encryption,
  application keys such as `jwt.algorithm: RS256`.
- Keys and certificates a repository holds, told apart by content: X.509
  certificates and requests, public and private keys (PEM or DER), JKS and
  JCEKS keystores, PKCS#12, SSH keys. Each finding names what it found
  (subject, key size or curve, signature, expiry).
- Hybrid-aware: classical crypto next to post-quantum code (ML-KEM, ML-DSA,
  SLH-DSA, BouncyCastle PQC, liboqs, `X25519MLKEM768`) is reported as *in
  transition*.
- Advice and references follow the final NIST IR 8547 (October 2026: every
  quantum-vulnerable public-key algorithm deprecated after 2030, disallowed
  after 2035) and the RFCs for ML-DSA in JOSE (RFC 9964) and hybrid TLS key
  exchange (RFC 9954, RFC 10024).
- Suggested fixes only where safe (AES-128 → AES-256); a rule for a
  Shor-broken algorithm that declares a fix is rejected.
- Rules are YAML data; your own load at run time with `--rules`.

### Analysis

- Values are followed to the crypto API through constants, `@Value`
  properties (resolved against every profile's configuration), variables,
  parameters, returned values, concatenations and branches, within and
  across files; findings show the path, file by file.
- Calls through interfaces reach every implementation; chained calls and
  untyped variables are typed from declared return types. `--classpath`
  reads compiled dependencies for their types (signatures only).
- Test code is told from production code by the project layout and
  labelled (`--exclude-tests` skips it). A folder of services is split into
  projects, each analyzed on its own.

### Reports

- Terminal: a summary by default, with a link to the HTML report;
  `--overview`, `--details`, `--compact`.
- HTML: one offline page that reads like an audit report, with a cover and
  chapters per severity, algorithm and project; findings open in VS Code (in
  the terminal's report) or on GitHub/GitLab and github.dev (in CI).
- SARIF 2.1.0 (code scanning, IDEs), CycloneDX 1.6 CBOM (validated against
  the schema), JSON and Markdown.

### Workflow

- `shorwatch` scans the current project; `shorwatch report` opens the HTML
  report; `shorwatch open` reopens the last one; `--watch` scans again on
  every change.
- `shorwatch ci` for pipelines: SARIF and HTML in one folder, the summary in
  the log linked to the report where GitHub Actions, GitLab CI, Jenkins or
  Azure Pipelines publish it, the GitHub job summary and an error
  annotation. Gates: `--fail-on`, `--fail-severity`; exit codes 0, 1, 2.
- Adoption on existing code: `shorwatch baseline` (fail only on new
  findings), `// shorwatch:ignore <rule> -- reason`, `.shorwatchignore`.
  Whatever is left out is counted in every report.

### Security

- Scanned repositories are treated as untrusted: private key bodies never
  reach a report, control characters never reach the terminal or CI logs,
  the HTML report renders text only under a Content-Security-Policy with no
  network access, and Markdown escapes markup from file names.
- Hostile shapes are bounded: files whose syntax nests deeper than 2,500
  levels are skipped with a warning (they used to overflow the stack), the
  scanning threads have a large stack, and the passes that were quadratic or
  worse over one long line, a long concatenation or a large `.properties`
  file are linear or bounded.
- Binaries with SHA-256 checksums and build provenance attestations;
  workflow actions pinned by commit; `cargo deny` in CI. See
  [SECURITY.md](SECURITY.md).

### Distribution

- Binaries for Linux, macOS and Windows; a Docker image
  (`ghcr.io/erwinquantum/shorwatch`, static, on Alpine) for CI systems
  without Rust. Rust 1.88 or later to build from source.
