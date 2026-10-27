# Contributing to Shorwatch

Thanks for helping! Most contributions are **new detections**, and those never
require touching Rust: rules are YAML data. This guide covers that first, then
code changes.

## Setup

Requires Rust 1.88 or later.

```sh
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check        # advisories and licenses; `cargo install cargo-deny`
```

[AGENTS.md](AGENTS.md) describes the architecture, the invariants the tests
enforce and the conventions, for coding agents and humans alike.

Snapshot tests use [insta](https://insta.rs). After a change that alters
output, review and accept snapshots with `cargo insta review` (install it with
`cargo install cargo-insta`), or regenerate them with
`INSTA_UPDATE=always cargo test` and review the diff in git.

## Adding a detection

Rules live in [`shorwatch-rules/rules/`](shorwatch-rules/rules/):

```
algorithms/<profile>.yaml        what an algorithm is and why it matters (written once)
markers/<name>.yaml              signs of post-quantum code (hybrid detection)
jvm/<library>/<profile>.yaml     the patterns one library exposes
config/<framework>/<profile>.yaml
keys/material/<profile>.yaml     keys and certificates a repository holds
```

### Covering a new library for an existing algorithm

Say you want to flag RSA in a library called `acme-crypto`. Create
`shorwatch-rules/rules/jvm/acme-crypto/rsa.yaml`:

```yaml
id: jvm.acme-crypto.rsa      # must match the file path
profile: rsa                 # must match the file name
platform: jvm                # must match the top folder
patterns:
  - call:
      type: com.acme.crypto.KeyPairs
      method: rsa
  - construct:
      type: com.acme.crypto.RsaSigner
  - field:
      type: com.acme.crypto.Algorithms
      matches: '^RSA_\d+$'
```

That's it: every file under `rules/` is embedded automatically. The message,
migration advice and NIST references come from `algorithms/rsa.yaml`.

### Pattern kinds

| Pattern | Matches | Example |
|---|---|---|
| `call` | `Type.method(...)` or `variable.method(...)` where the variable has that type; optional `arg: { index, matches }` regex on a literal argument; optional `origin: { index, matches }` on the factory that created the variable (`KeyGenerator.getInstance("AES")`), where an unknown origin still matches | `Cipher.getInstance("RSA/ECB/...")`, `generator.init(128)` |
| `construct` | `new Type(...)`, with the same optional `arg` | `new RSAEngine()` |
| `field` | A static constant `Type.NAME`, with an optional `matches` regex on the name | `JWSAlgorithm.RS256` |
| `literal` | A string literal anywhere in the code, by `matches` regex; optional `unless_call` regex on the methods it is passed to. Only for names specific enough to stand alone | `"TLS_ECDHE_RSA_WITH_..."`, but not in `setExcludeCipherSuites(...)` |
| `property` | A config entry: `key` regex, optional `matches` regex on the value | `server.ssl.ciphers: TLS_RSA_...` |
| `key` | A key or certificate in a key file: `algorithm` and/or `signature` regexes | `key: { signature: '^SHA1with' }` |

Types are fully qualified; Shorwatch resolves imports, `var`, fields and
parameters, so code using simple names still matches. A name without an
import only matches types of the file's own package, its `import a.b.*`
packages and `java.lang` (a same-package `KeyType` is not Azure's), unless the
file uses a Java 25 `import module`. Arguments match whatever value
Shorwatch can follow to them: literals, constants (of any class),
`@Value("${...}")` properties, and the data flow within and across files
(variables, parameters, returned values).

To see what your rule does on real code without writing a test, scan a
project with it: `shorwatch --rules ./my-rules/ --details path/to/project`.

Write regexes in **single quotes** (`'^RSA$'`): in single-quoted YAML a
backslash is literal, which is what regexes want.

### Adding a new algorithm

Add `algorithms/<profile>.yaml` with `algorithm`, `category` (`shor` or
`grover`), `severity`, `title`, `message`, `suggestion`, `references` and
usually `hybrid: pqc`. Two rules the tests enforce:

- **Shor-category algorithms never get an automatic `fix`.** Migrating away
  from RSA or ECC changes the protocol; the advice must stay a human decision.
- **Shor-category profiles reference FIPS 203 or FIPS 204.**

### Tests for your rule

Add a folder under
[`shorwatch-rules/tests/fixtures/`](shorwatch-rules/tests/fixtures/) with:

- `Vulnerable.java` (or `.yml`, `.properties`): real-looking code that must be
  flagged;
- `Hybrid.java`: the same next to post-quantum code, expected `in_transition`;
- `Clean.java`: look-alikes that must **not** be flagged (it is asserted to
  produce zero findings).

JVM rules cover Java and Kotlin alike. Next to a `.java` fixture, add its
Kotlin twin (`Vulnerable.kt`, written the Kotlin way): a test requires both to
produce the same findings.

Each folder is analyzed as a small project with *all* rules, then
snapshotted. Run the tests and review the new `.snap` files: they are the
specification of what your rule does.

## Changing code

The workspace is hexagonal; `shorwatch-core` never does I/O and never depends
on the other crates.

| Crate | Responsibility |
|---|---|
| `shorwatch-core` | Intermediate model, rule model and validation, engine, cross-file linking |
| `shorwatch-rules` | Embedded YAML rules and the loader that assembles profiles and rules |
| `shorwatch-langs` | Frontends: Java and Kotlin (tree-sitter, one shared JVM resolver), YAML (tree-sitter), `.properties`, key material, class files |
| `shorwatch-report` | Pure renderers: terminal, SARIF, CBOM, JSON, Markdown, HTML |
| `shorwatch-cli` | The `shorwatch` binary: commands, file discovery, the scan pipeline, baselines and suppressions |

Conventions:

- **One responsibility per file.** When a file starts mixing concerns, split
  it into a module folder; tests go in a sibling `tests.rs`.
- **Refactors keep snapshots unchanged.** `tests/inventory.rs` snapshots every
  pattern; fixture snapshots pin every finding.
- Comments explain *why*, not *what*.
- English everywhere; commit messages in the imperative mood, one logical
  change per commit.

## Reporting a false positive or a missed detection

Open an issue with the smallest Java, Kotlin or config snippet that
reproduces it. It will very likely become a fixture. Security issues go
through [SECURITY.md](SECURITY.md), not an issue.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
