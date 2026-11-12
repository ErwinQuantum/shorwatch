# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- NuGet inventory: the cryptographic packages a .NET project declares in
  `*.csproj`, `Directory.Packages.props` (central versions, scope `managed`) and
  `packages.config`, with `$(Property)` versions resolved. Seven .NET libraries
  are known (BouncyCastle for .NET, whose first post-quantum release is 2.5.0,
  the IdentityModel and jose-jwt packages, SSH.NET...) and the Azure, AWS and
  Google KMS entries gain their NuGet ids. The CBOM lists them with
  `pkg:nuget/` package URLs; the JSON `dependencies` carry an `ecosystem`.
- A folder with a `.sln` or `Directory.Build.props` is a project root.
- C# data flow across files: properties are read like accessors
  (`options.Algorithm`), record components and primary-constructor parameters
  take the arguments of `new`, and object initializers (`new Aes { KeySize = 128 }`)
  are setter calls.
- Every report says which languages it analyzed (`analyzed: 120 Java · 12 C#`)
  and which source files it skipped for want of a frontend (`NOT analyzed: 340
  Python · 80 Go`). Zero findings in a project of a language Shorwatch does not
  read no longer looks like a clean bill of health. Terminal, Markdown, HTML and
  JSON (`summary.languages`, `summary.unanalyzed`).
- A test that a rule never fires on a file of another platform.
- **C# frontend** (tree-sitter-c-sharp) on the resolver Java and Kotlin share, now
  named `managed`: `using`s and aliases, namespaces, types, `var` and target-typed
  `new()`, `const` / `readonly` constants, property assignments as setter calls
  (`aes.KeySize = 128`), `a?.B()`, call chains, and the same in-file and
  cross-file data flow.
- A `dotnet` platform and 7 rules for the base class library
  (`System.Security.Cryptography`): RSA, ECDsa, ECDiffieHellman, DSA, SHA-1,
  Triple DES and AES with a 128-bit key. Names checked against Microsoft's
  documentation.
- JOSE rules for **jose4j** (`AlgorithmIdentifiers`,
  `KeyManagementAlgorithmIdentifiers`, `ContentEncryptionAlgorithmIdentifiers`,
  the names passed to `setAlgorithmHeaderValue`, its RSA and EC JWK generators)
  and **fusionauth-jwt** (the `Algorithm` values and the RSA, RSA-PSS, EC and
  EdDSA signer and verifier factories). Names checked against both libraries'
  sources. Before, both only showed up in the dependency inventory.
- Nimbus `RSAKey.parse` / `load` and `ECKey.parse` / `load`.
- SSH key type constants: JSch `HostKey.SSHRSA`, `SSHDSS`, `ECDSA*`, `ED*` and
  Apache SSHD `KeyPairProvider.SSH_RSA`, `SSH_DSS`, `SSH_ED25519`,
  `ECDSA_SHA2_NISTP*` (and their certificate forms).
- Classical groups passed to `SSLParameters.setNamedGroups`.
- Two rule conditions: `with_arg` (a `call` constrains a second argument) and
  `in_call` (a `literal` counts only inside a named method).

- Field reads know the call they are an argument of (`unless_call` on `field`
  patterns): SHA-1 given to PBKDF2, HKDF or HMAC is not reported.
- The scan skips `bin` and `obj` (.NET build output) and generated C#
  (`*.Designer.cs`, `*.g.cs`, `*.generated.cs`, EF `*ModelSnapshot.cs`), and
  recognises .NET test projects (`Acme.Tests/`) as test code.

### Changed

- `link` works on one platform at a time: a Java method never receives the
  arguments of a C# call that shares its name and arity.

### Fixed

- `System.setProperty(key, value)` with a classical group name was reported for
  any key; it is now reported only for `jdk.tls.namedGroups`.

## [0.2.0] - 2026-11-06

Shorwatch now follows more of the ways code names an algorithm, reads more
places where one is chosen, and explains every finding. On the same code a scan
reports more than 0.1.0 and loses nothing: on 8 open-source projects (20,000
files) no finding disappeared and 63 were added, and every production finding
was read by hand (none named an algorithm the code does not use).

### Added

- **A dependency inventory.** The cryptographic libraries a project declares in
  `pom.xml`, `build.gradle`, `build.gradle.kts` and `libs.versions.toml` (found
  by file name) are listed with their version and, where the catalog knows it,
  whether that version can do post-quantum cryptography (BouncyCastle from
  1.79). About 20 libraries are known (BouncyCastle, Nimbus, jjwt, JSch, Tink,
  the cloud KMS clients...). They are an inventory, not findings: the summary
  counts them, the JSON report lists `dependencies`, the Markdown and HTML
  reports have a section, and the CBOM carries them as `library` components
  with a package URL. They feed no gate, baseline or SARIF result. The catalog
  is data (`rules/libraries/<id>.yaml`) and `--rules` directories may add their
  own.
- **A page for every algorithm** in `docs/algorithms/`: why it is a problem, how
  urgent it is and what to do, plus an introduction to Shor, Grover and
  harvest-now-decrypt-later. Every finding's references now start with a link to
  its page, in the terminal, SARIF, JSON and HTML reports, and a test keeps
  profiles and pages in step.
- **Six rules for places that were not read**: Jasypt's
  `jasypt.encryptor.algorithm` over Triple DES, AWS KMS `DataKeySpec.AES_128`,
  Spring Security's SHA-1 password encoders, application-defined JWE settings
  (`alg` and `enc` keys: two rules), and Quarkus's MicroProfile JWT keys that
  name no algorithm (RS256 by default). 133 rules in all.
- **Two rule conditions**, for library defaults: `unless_chain` (a method called
  later on the same call chain) and `unless_property` (another key of the same
  file).

### Changed

- **More names are recognised.** Every algorithm and alias the JDK 21 providers
  register (632 names) and every name BouncyCastle 1.85 registers through the
  JCA (4,175) is checked by a test. Among the names that must be reported,
  v0.1.0 reported 38% of the JDK's and 42% of BouncyCastle's; now all of them.
  That covers the OIDs of RSA, DSA and ECDSA signatures (SHA-3 included), `PSS`,
  `EllipticCurve`, the X25519/X448/Ed25519/Ed448 OIDs, `AlgorithmParameters`,
  `KEM.getInstance("DHKEM")`, `AESWrap_128`, `DSA` and `DSS` (which sign with
  SHA-1), OpenSSL cipher names next to the IANA ones (including static RSA
  suites such as `AES256-SHA`, and Kafka's `ssl.cipher.suites`), JOSE names read from text
  (`JWEAlgorithm.parse("ECDH-ES")`), XML Signature URIs, `shaHex`, `DESedeWrap`
  and password-based Triple DES. Post-quantum and composite names are not
  reported as classical algorithms.
- **More ways of choosing an algorithm are followed to the crypto call.**
  - Through an enum: `Cipher.getInstance(kind.getJceName())` where the constants
    carry the algorithm (`LEGACY("RSA")`), `algorithm.name()`, and the Kotlin
    equivalents. Every constant that can reach the call is reported. A specific
    constant (`Kind.LEGACY.getJceName()`) is not read.
  - Through `@ConfigurationProperties`: a class, Java record or Kotlin data class
    with `prefix = "app.jwt"` has its fields bound to `app.jwt.*`, relaxed
    binding included, with the field's initializer as the default.
  - Library defaults: `NimbusJwtDecoder.withJwkSetUri(...)` and
    `withJwkSource(...)` (plain and reactive) verify RS256 unless the chain
    chooses another algorithm, as does Spring Boot's `jwk-set-uri` without
    `jws-algorithms`.
- **A rule reports a line once.** A second match of the same rule on the same
  line (one cipher suite under its IANA and OpenSSL names, two algorithm names in
  one expression) is no longer a second finding; the baseline already treated
  them as one. A scan can therefore report fewer findings than before for that
  code.
- The reports in `examples/output` were regenerated.

### Fixed

- A field of a configuration class was reported with its initializer even when
  the configuration overrides it (`algorithm = "SHA256withECDSA"` in code,
  `SHA1withRSA` in `application.yml`): the value that runs is now the one
  reported.

### Security

- Build files are read as untrusted input: XML external entities are never read,
  nesting and resolved coordinates are bounded, and the readers are linear in
  the file.

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
