# CLAUDE.md — Shorwatch

Context for AI coding agents (and humans) working on this repository. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow. Personal
notes can go in a git-ignored `CLAUDE.local.md`.

## What this is

Shorwatch is a SAST tool in Rust that finds quantum-vulnerable cryptography in
source code and configuration, and suggests migrating to the NIST post-quantum
standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA). It analyzes statically through
tree-sitter (no compiling, no binaries): **Java** and **Kotlin** sources plus
**YAML / `.properties`** configuration (Spring Boot). Everything in the repo
(code, comments, rules, docs, commits) is in English.

## Architecture (hexagonal workspace)

| Crate | Role | May depend on |
|---|---|---|
| `shorwatch-core` | Pure domain: IR (`SourceUnit`, `Fact`, `Scope`), rule model + validation, engine (`analyze`), cross-file `link`, `Finding`. **No I/O.** | serde, regex, thiserror only |
| `shorwatch-rules` | Built-in YAML rules (embedded by `build.rs`), `Catalog` assembling profiles + rules, `load_dir` for external rules | core |
| `shorwatch-langs` | `Frontend` trait; `JavaFrontend` (tree-sitter-java), `KotlinFrontend` (tree-sitter-kotlin-ng), both on the shared `jvm` resolver; `YamlFrontend` (tree-sitter-yaml), `PropertiesFrontend` (hand-written). Nothing tree-sitter leaks out | core |
| `shorwatch-report` | Pure renderers over a `Scan`: terminal (banner, detailed/compact), SARIF 2.1.0, CycloneDX CBOM, JSON, Markdown | core |
| `shorwatch-cli` | `shorwatch scan` / `shorwatch rules`: clap args, `ignore` walker, `layout` (test vs production code by path), rayon pipeline, output, exit codes | all |

Pipeline (what the CLI does): lower every file with its frontend → `link`
all units of the project → `analyze` each unit → report.

Module map (one responsibility per file, tests in sibling `tests.rs`):

```
core/src/  ir/{language, location, unit, types, facts}  rule/{mod: model, error, compile}
           engine/{mod: analyze + findings, matching, hybrid, fix}  link.rs  finding.rs
rules/src/ lib.rs (public API)  catalog.rs (files → assembled rules)  error.rs  build.rs
langs/src/ jvm/{mod: JvmFile, model, resolve}  java/{mod: traversal, syntax, literals}
           kotlin/{mod: traversal, syntax, literals}  config/{properties, yaml}  span.rs
```

### Invariants (do not break)

- `shorwatch-core` never imports cli/report/langs, never touches the file system.
- Rules are data. A new detection must not require touching the engine.
- Rules target a **platform** (`jvm`, `config`), not a language: JVM rules
  describe library APIs that Java and Kotlin call identically.
- **Shor-category rules can never carry a `fix`** (`RuleError::FixNotAllowed`).
  Their `suggestion` is educational text only.
- A fix is never offered when the matched value was resolved indirectly
  (`Arg::resolved_via`: a constant or a `${property}`).
- Hybrid detection: markers (`import` / `literal` / `type` regexes) are
  searched in the same scope as the finding (default: the enclosing class);
  **imports count for the whole file**; literal markers also see config
  values. Match → `Status::InTransition`.
- Every Shor rule must reference FIPS 203 or FIPS 204 (enforced by a test).
- No general data flow yet: a value only resolves when it is a literal, a
  same-file `final` constant, a static constant/import, or an `@Value`
  field/parameter used *directly* as the argument. Likewise a receiver's
  *origin* (`Call.receiver_origin`, the factory args of `x = T.getInstance(..)`)
  comes only from the variable's own initializer (or a Kotlin scope-function
  receiver). `origin` patterns let unknown origins match (no lost
  detections). Anything else is `ArgValue::Unknown`. That is the future taint layer's job; don't hack around
  it in rules.

### Frontends

- **JVM resolver** (`langs/src/jvm/`): phase one (a frontend's traversal)
  fills a `JvmFile` (scopes, imports, member imports, symbols, pending
  facts); `JvmFile::resolve` (phase two) is shared by Java and Kotlin.
  `Receiver::Type` carries a type known from syntax (Kotlin implicit receivers).
- **Java** (`langs/src/java/`: `mod.rs` traversal, `literals.rs`,
  `syntax.rs`, `tests.rs`): two-phase lowering (collect
  scopes/imports/declarations/pending facts, then resolve). Receiver types via declarations (incl. `var` with
  `new T()`, casts, `T.getInstance()`), `this.x`, imports, FQNs. Same-file
  `final` constants (also after use, `Owner.NAME`, interface fields). Static
  field reads → `FactKind::Field` (`JWSAlgorithm.RS256`, `Jwts.SIG.ES256`);
  instance fields dropped. Single static imports resolve bare constants and
  unqualified calls unless shadowed. `@Value("${key:default}")` on fields and
  parameters → `ArgValue::Injected` (SpEL `#{}` ignored).
- **Kotlin** (`langs/src/kotlin/`): `Name(...)` is a constructor when `Name`
  looks like a type (upper-case start *and* a lower-case letter, so `RSA256(...)`
  stays a call); member imports (`...JWSAlgorithm.RS256`) = Java static
  imports (owner upper-case, member not type-like); `as` aliases for types;
  `val`/`const val` with a literal = constant anywhere; `companion object`
  members live in the class scope; scope functions: `apply`/`run`/`with` set an
  implicit receiver for unqualified calls in the lambda, `also`/`let` type
  `it` (or the named lambda parameter); lambdas are `Method` scopes named
  `<lambda>`. String literals are decoded from their joined text (the grammar
  leaves `"$x"` and unicode escapes as plain content): templates are `None`.
  `@Value("\${k}")` on properties, constructor and function parameters
  (function parameter annotations are preceding `parameter_modifiers` siblings).
- **YAML / properties**: flatten keys like Spring (`a.b[0].c`), one
  `FactKind::Property` per scalar, located at the value. Multi-document YAML,
  flow/block collections, `\` continuations, CRLF. Comments produce nothing.
- `core::link`: fills `Injected.resolved` from config units (production code
  sees production config only; test code sees both) with relaxed
  binding (`signingAlgorithm` = `signing-algorithm`); list keys collect their
  elements; every profile's value is a candidate; default if unset.
- Columns are Unicode code points (SARIF `unicodeCodePoints`).
- `SourceUnit::role` (`CodeRole::Production | Test`) is set by whoever knows
  the project layout (the CLI's `layout.rs`, from the path relative to the
  scan root); `analyze` copies it to every `Finding`. Sources that are not
  UTF-8 are decoded as ISO-8859-1 (`.properties` files often are).

## Rules (`shorwatch-rules/rules/`)

```
algorithms/<profile>.yaml        what & why, once: category, severity, title,
                                 message, suggestion, references, hybrid
markers/pqc.yaml                 shared hybrid markers (`hybrid: pqc`)
jvm/<library>/<profile>.yaml     patterns only + `profile:`; id jvm.<library>.<profile>
config/<framework>/<profile>.yaml
```

Rule fields override profile fields. A rule file may also be self-contained.
Tests enforce: id = path, platform = top folder, file name = profile, every
profile/marker set used. `build.rs` embeds everything under `rules/`.

Profiles (17): `rsa dh ecdh ecdsa ec eddsa dsa elgamal` (shor, high),
`aes-128` (grover, low, fix only in `jvm/jca`), `sha1` `3des` (grover,
medium, no fix), `jose-rsa jose-ecdsa jose-eddsa jose-ecdh` (shor, JWT advice),
`jose-aes-128` (grover), `tls-key-exchange` (shor, TLS suites).

Libraries (87 rules): `jvm/` jca, bouncycastle, bouncycastle-pkix, openpgp,
jsch, apache-sshd,
xml-security (JSR 105 + Santuario), android-keystore, spring-security, jjwt,
nimbus (incl. `JWSAlgorithm.Family`), auth0, i2p-eddsa, commons-codec, guava
· `config/` spring-boot
(jws-algorithms, public-key-location, `*.ssl.ciphers`), spring-cloud-config
(`encrypt.key-store`, `encrypt.rsa`), app (custom `*.alg`/`*.algorithm`
keys with exact JOSE names).

Notable design calls: generic `"EC"` keys and EC JWKs → `ec` profile (could
be ECDH or ECDSA); SHA-1 excludes HMAC-SHA1, PBKDF2-SHA1, OAEP-SHA1; one value
may yield several findings when it really has several problems
(`SHA1withRSA`, `ECDH_ES_A128KW`, a 3DES+AES-128 cipher list).

## Conventions

- **Adding a rule**: create `rules/<platform>/<library>/<profile>.yaml` with
  `id`, `profile`, `platform`, `patterns` (new algorithm? add a profile under
  `algorithms/` too). Add fixtures in `tests/fixtures/<folder>/` and run the
  snapshot tests, review the `.snap` files. No registration needed.
- **Fixtures**: each folder is a mini project (all files lowered and linked
  together). `Clean.*` must yield zero findings (asserted). Every `X.java`
  has a Kotlin twin `X.kt` written idiomatically; `kotlin_twins_find_what_java_finds`
  requires the same (rule, status, hybrid, fix) multiset. Fixtures are
  analyzed with *all* rules, so overlaps show.
- `tests/inventory.rs` snapshots every pattern grouped by algorithm: rule-file
  refactors must leave it unchanged.
- Regexes in YAML go in **single quotes** (`'^org\.bouncycastle\.'`), where `\`
  is literal. The literal marker uses `(^|[^a-z])` instead of `\b` so
  `X25519MLKEM768` matches.
- `serde_yaml` is archived → `serde_yaml_ng` with `singleton_map_recursive`
  so enums are written `- call: {...}`, not `!call`.
- **Atomic modules**: one responsibility per file. When a file starts mixing
  concerns (or passes ~500 lines of non-test code), split it into a module
  folder; tests go in a sibling `tests.rs`. Refactors must leave fixture
  snapshots and the inventory unchanged.
- Comments: explain *why*, sparse. Match the surrounding style.
- Commits: one per logical step, English, imperative mood.

## Commands

```sh
cargo test --workspace
INSTA_UPDATE=always cargo test -p shorwatch-rules   # or `cargo insta review`
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Toolchain: stable, edition 2024, MSRV 1.88 (`ignore` uses let chains).
`.gitattributes` forces LF: findings carry byte offsets, so fixtures must not
change line endings.

## CBOM output

`report/src/cbom.rs` emits CycloneDX 1.6: one `cryptographic-asset` per
algorithm, with `evidence.occurrences`. Each profile in `rules/algorithms/`
has a `crypto:` block (primitive, functions, parameter set, NIST quantum
security level; tests require it and Shor profiles must be level 0). CI
validates the output against the official schema with
`.github/scripts/validate_cbom.py`.
