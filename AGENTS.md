# AGENTS.md — Shorwatch

Context for AI coding agents (and humans) working on this repository. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow. Personal,
untracked notes can go in a git-ignored `AGENTS.local.md` (or
`CLAUDE.local.md` for Claude Code).

## What this is

Shorwatch is a SAST tool in Rust that finds quantum-vulnerable cryptography in
source code and configuration, and suggests migrating to the NIST post-quantum
standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA). It analyzes statically through
tree-sitter (no compiling, no binaries): **Java** and **Kotlin** sources plus
**YAML / `.properties`** configuration (Spring Boot), the **key material**
a repository holds (certificates, keys, keystores) and the cryptographic
**libraries its build files declare** (`pom.xml`, Gradle, version catalogs). Everything in the repo
(code, comments, rules, docs, commits) is in English.

## Architecture (hexagonal workspace)

| Crate | Role | May depend on |
|---|---|---|
| `shorwatch-core` | Pure domain: IR (`SourceUnit`, `Fact`, `Scope`), rule model + validation, engine (`analyze`), cross-file `link`, `Finding`, and the dependency `inventory` (`LibraryCatalog`, `Dependency`). **No I/O.** | serde, regex, thiserror only |
| `shorwatch-rules` | Built-in YAML rules and known libraries (embedded by `build.rs`), `Catalog` assembling profiles + rules, `load_dir` / `load_dir_libraries` for external ones | core |
| `shorwatch-langs` | `Frontend` trait; `JavaFrontend` (tree-sitter-java), `KotlinFrontend` (tree-sitter-kotlin-ng), both on the shared `jvm` resolver; `YamlFrontend` (tree-sitter-yaml), `PropertiesFrontend` (hand-written); `MavenFrontend` (`pom.xml`, quick-xml events), `GradleFrontend` (a tokenizer), `VersionCatalogFrontend` (line-based TOML), which a file's exact *name* selects (`for_path`). Nothing tree-sitter leaks out | core |
| `shorwatch-report` | Pure renderers over a `Scan` (findings, sources, `projects`, `links`: editor `vscode://` root only for the temporary report, repository host URL templates in CI): terminal (banner; summary + HTML report link by default, `--overview`, `--details`, `--compact`, the failing verdict), SARIF 2.1.0, CycloneDX CBOM, JSON, Markdown, HTML (`html/`: one offline page, data embedded as JSON and rendered with `textContent` only, CSP forbids the network; an editorial cover + hash-routed chapters `#/findings?sev=&project=&alg=&cat=&f=`, grouped by file, tests folded) | core |
| `shorwatch-cli` | `shorwatch [scan]` (no command = scan) / `report` (scan + open) / `ci` (SARIF + HTML in `shorwatch-report/`, CI artifact links) / `open` (last HTML report, in the browser) / `rules`; `--watch` polls mtimes: clap args, `ignore` walker, `layout` (test vs production code by path), `projects` (top-most build roots of a scanned folder), rayon pipeline (one `link` per project), output (`--html`, temporary HTML on terminals, `--report-url`), exit codes (`--fail-on`, `--fail-severity`) | all |

Pipeline (what the CLI does): lower every file with its frontend → group
units by project → `link` each project's units → `analyze` each unit →
make text from scanned files printable (`printable.rs`) → set suppressed
findings aside (`suppress/`) → report. A scanned folder with no build file whose subfolders (2 levels) hold
several build roots (`pom.xml`, Gradle, `.git`...) is several projects;
several plain paths (`src/ config/`) stay one project so `@Value` still
resolves across them.

Module map (one responsibility per file, tests in sibling `tests.rs`):

```
core/src/  ir/{language, location, unit, types, facts, library}  rule/{mod: model, error, compile}
           inventory/{mod: Dependency + dependencies(), spec: LibrarySpec + LibraryCatalog, version}
           engine/{mod: analyze + findings, matching, hybrid, fix}
           link/{mod, library, hierarchy, receivers, flow, config}  finding.rs
rules/src/ lib.rs (public API)  catalog.rs (files → assembled rules, libraries)  error.rs  build.rs
langs/src/ jvm/{mod: JvmFile, model, resolve, flow}  java/{mod: traversal, syntax, literals}
           kotlin/{mod: traversal, syntax, literals}  config/{properties, yaml}  span.rs
           bytecode/{mod: class -> Library, classfile: JVMS parser}
           keys/{mod: format sniffing + labels, der, pem, x509, keystore, ssh}
           build/{mod, maven, gradle, catalog}  depth.rs (nesting bound)
cli/src/   args, pipeline, discover, layout, projects, classpath (--classpath: dirs, jars, jmods, @file)
           printable (control characters out), suppress/{mod: apply, inline: `shorwatch:ignore`,
           baseline: shorwatch-baseline.json}, gate (--fail-on/--fail-severity), output,
           browser (--open, `shorwatch open`), ci, watch
report/src/ terminal/{mod: views + summary, overview, detailed, compact, style, wrap, banner}
           html/{mod: payload, report.html/css/js}  sarif cbom json markdown summary links suppression
```

### Invariants (do not break)

- `shorwatch-core` never imports cli/report/langs, never touches the file system.
- Rules are data. A new detection must not require touching the engine.
- Rules target a **platform** (`jvm`, `config`), not a language: JVM rules
  describe library APIs that Java and Kotlin call identically.
- **Scanned repositories are untrusted.** Text from them reaches reports
  only through `printable` (no control characters) and, in HTML, only as
  `textContent`; links in the page are limited to `#`, `http(s)://` and
  `vscode://`, and rule references must be http(s). Private key bodies never
  reach the text reports show (`keys::pem::redact_private_keys`). Binary
  parsers are bounded; never `read_to_end` input without a size limit.
  Syntax trees nest at most `depth::MAX_DEPTH` levels (deeper files are
  skipped with a warning), so recursion over a tree is safe on the scanning
  threads' large stack; and no per-fact work may scan from the top of the
  file (`span::Lines` for positions, bounded climbs for `Node::parent()`,
  which costs the node's depth).
- **Shor-category rules can never carry a `fix`** (`RuleError::FixNotAllowed`).
  Their `suggestion` is educational text only.
- A fix is never offered when the matched value was resolved indirectly
  (`Arg::resolved_via`: a constant or a `${property}`).
- Hybrid detection: markers (`import` / `literal` / `type` regexes) are
  searched in the same scope as the finding (default: the enclosing class);
  **imports count for the whole file**; literal markers also see config
  values. Match → `Status::InTransition`.
- Every Shor rule must reference FIPS 203 or FIPS 204 (enforced by a test).
- Values resolve, in order: a literal, a same-file `final` constant, a static
  constant/import, an `@Value` field/parameter used directly; otherwise
  **in-file data flow** (`langs/src/jvm/flow.rs`): assignments (initializers
  included), parameters fed by calls in the same file, returns of the file's
  methods, concatenations, `?:`/`switch`/`if`/`when` branches. It yields
  `ArgValue::OneOf` candidates, each with its `FlowStep` path, which becomes
  `Finding::flow`. Order-insensitive, bounded (depth 6, 16 candidates);
  overloaded targets and cycles stay unknown. A call's return binds the
  callee's parameters to that call's arguments.
- **Enums that carry an algorithm**: each constant with arguments is lowered as
  a construction of the enum (`LEGACY("RSA")` = `new Kind("RSA")`), so the
  constructor parameter, the field it sets and the getter that returns it
  resolve through the existing machinery to every constant's value. `name()` /
  `toString()` (Kotlin `.name`) are synthetic `MethodSummary`s listing the
  constants (`jvm/flow.rs::enum_name_summaries`); a Kotlin primary-constructor
  `val` is published as an accessor, and `k.prop` on a typed variable is a
  `Returns` candidate. A *specific* constant (`Kind.LEGACY.getJceName()`) is
  not resolved: the union of all constants would be wrong for it.
- **`@ConfigurationProperties`**: a type annotated with a prefix binds its
  fields (and a record's or Kotlin primary constructor's properties) to
  `<prefix>.<field>`, as `ArgValue::Injected` with the field's literal
  initializer as default (`jvm/resolve.rs::bind_configuration_properties`).
  Getters, record accessors and Kotlin property reads then resolve through the
  same cross-file flow as `@Value`; relaxed binding is `link::config`'s.
  Nested objects and collections are not bound.
- **Cross-file data flow** (`core/src/link/`): what a file cannot resolve
  stays as `ArgValue::Param` (a parameter, constructors included),
  `ArgValue::Returns` (another type's method, with the call's args) or
  `ArgValue::Constant` (`Owner.NAME` of another file) candidates. Frontends
  publish `MethodSummary`s (returns + declared return type), `TypeDecl`s
  (supertypes) and `ConstantDecl`s. `link` builds the type `hierarchy`, types
  chained receivers (`receivers`: `X.provider().m()` from `provider()`'s
  return type, declared by the receiver's type or inherited; chains up to 8
  calls, typed from the innermost out; also variables with no written type,
  `Symbol::call`), then `flow` matches calls/constructions by name +
  arity + any *related* type (the type, its supertypes and subtypes: calls
  through interfaces reach every implementation), up to 3 hops, and tags
  each `FlowStep` with its file. Calls are indexed by declared receiver type
  and parameters memoized: never scan every call per parameter (Kafka went
  from 5 s to 30 s once). Overloads stay unknown (unique per declaring
  type). Production code takes no values from test code.
- **Compiled dependencies** (`--classpath`, `langs/src/bytecode/`): class
  files give a `Library` of `TypeDecl`s and `MethodSummary`s with return
  types (signatures only, never bodies: values never come from a library).
  `link::library::relevant` keeps only what the project's call chains reach
  (a 1 GB `~/.m2` has 400k types; a project reaches a few thousand): never
  feed the whole library to `hierarchy` or `receivers`.
- **Suppressions** never hide silently: `suppress::apply` moves ignored
  (`shorwatch:ignore`) and baseline-known findings to `Scan::suppressed`;
  every report counts them, SARIF leaves them out (GitHub ignores
  `suppressions` and would open alerts), the CBOM
  still inventories them, and gates ignore them. A finding's identity across
  scans is `report::fingerprint` (rule + whitespace-normalised line, or the
  key label): never the line number.
- **Dependencies are an inventory, never findings.** A library declared in a
  build file becomes a `FactKind::Dependency`; `core::dependencies` matches it
  against the `LibraryCatalog` (`rules/libraries/<id>.yaml`, data like rules)
  into `Scan::dependencies`. They have no category, severity or status, feed
  no gate, baseline or SARIF result, and the CBOM lists them as `library`
  components. A library claims post-quantum support only when the catalog
  names the first version (`post_quantum.since`, verified against its release
  notes); a version that is not a plain number (range, `${x}`, unset) is
  `Unknown`, never guessed. Build files are found by file *name*, not by
  extension, and are untrusted: bounded nesting and coordinates, no
  external entities.
- **Defaults are patterns with conditions**: `call` takes `unless_chain` (a
  regex on the methods called later on its result: `FactKind::Call::chain`,
  filled by both JVM frontends) and `property` takes `unless_property` (a
  regex on another key of the same file). They let a rule report a library
  default (`withJwkSetUri(u).build()` verifies RS256) only when nothing
  chooses another.
- **A rule reports a line once** (`analyze`): a second match of the same rule
  on the same line (two suite names, `Family.EC.contains(a)` beside
  `new ECDSAVerifier(k)`) is folded into the first, which is also how
  `report::fingerprint` already identifies findings. Findings with a fix and
  key findings (their line is not where the key is) are never folded.
- A receiver's *origin* (`Call.receiver_origin`) still comes only from the
  variable's own initializer; `origin` patterns let unknown origins match
  (no lost detections). Don't hack around missing flow in rules.

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
- **Key material** (`langs/src/keys/`, platform `keys`, `Language::KeyMaterial`):
  formats told apart by content, never by extension. One `FactKind::Key`
  (algorithm, bits, curve, signature, `label`) per key; `Finding::detail`
  carries the label, since binary files have no line to show (their
  findings sit at 1:1 and `lower_bytes` keeps no text). Hand-written DER
  reader: no ASN.1 dependency. A self-signed certificate's (or a CSR's)
  signature is not a fact (nothing verifies it, so no SHA-1 finding);
  certificates a keystore only *trusts* are grouped per algorithm when
  there are several (Keycloak's truststores copy ~290 JDK CAs); a PKCS#12
  key whose certificate is present is not repeated. Encrypted content is
  skipped silently. Fixtures are generated with OpenSSL 3.5 (ML-DSA,
  ML-KEM), keytool and ssh-keygen; private key fixtures start with a
  "throwaway" comment line.
- **YAML / properties**: flatten keys like Spring (`a.b[0].c`), one
  `FactKind::Property` per scalar, located at the value. Multi-document YAML,
  flow/block collections, `\` continuations, CRLF. Comments produce nothing.
- `core::link`: fills `Injected.resolved` from config units (production code
  sees production config only; test code sees both) with relaxed
  binding (`signingAlgorithm` = `signing-algorithm`); list keys collect their
  elements; every profile's value is a candidate; default if unset.
- Columns are Unicode code points (SARIF `unicodeCodePoints`).
- `TypeRef::packages`: a name no import qualifies can only be a type of the
  file's package, an `import a.b.*` package or an implicit one (`java.lang`,
  Kotlin defaults); a Java 25 `import module` lifts the restriction.
- `FactKind::Literal::calls`: the methods the literal is an argument of,
  innermost first, up to the enclosing block or lambda. `literal` patterns
  use it for `unless_call` (`setExcludeCipherSuites`).
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
Every profile has a page, `docs/algorithms/<profile>.md` (why it is a problem,
urgency, what to do), and its first reference links to it; a test enforces
both directions. A new profile needs its page; keep the tone plain and every
technical claim traceable to a standard or paper.
Tests enforce: id = path, platform = top folder, file name = profile, every
profile/marker set used. `build.rs` embeds everything under `rules/`.

Rules for key material (`keys/material/`) match `key: { algorithm,
signature }` and override the profile's `message` (the profiles talk about
code).

Profiles (17): `rsa dh ecdh ecdsa ec eddsa dsa elgamal` (shor, high),
`aes-128` (grover, low, fix only in `jvm/jca`), `sha1` `3des` (grover,
medium, no fix), `jose-rsa jose-ecdsa jose-eddsa jose-ecdh` (shor, JWT advice),
`jose-aes-128` (grover), `tls-key-exchange` (shor, TLS suites).

Libraries (133 rules): `jvm/` jca, bouncycastle, bouncycastle-pkix, openpgp,
jsch, apache-sshd, tls (suite-name literals, `jdk.tls.namedGroups`), okhttp,
aws-kms, azure-keyvault, gcp-kms, tink, opensaml,
xml-security (JSR 105 + Santuario), android-keystore, spring-security, jjwt,
nimbus (incl. `JWSAlgorithm.Family`), auth0, i2p-eddsa, commons-codec, guava
· `config/` spring-boot
(jws-algorithms, public-key-location, `*.ssl.ciphers`), spring-cloud-config
(`encrypt.key-store`, `encrypt.rsa`), quarkus (`mp.jwt.verify.publickey*` without an algorithm), jasypt (`jasypt.encryptor.algorithm`),
app (custom `*.alg`/`*.algorithm`/`*.enc` keys with exact JOSE names) · `keys/` material (RSA, EC, ECDSA, DSA, EdDSA,
X25519/X448, DH keys; SHA-1 certificate signatures).

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
cargo deny check                                     # advisories, licenses
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
