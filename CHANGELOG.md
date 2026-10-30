# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
