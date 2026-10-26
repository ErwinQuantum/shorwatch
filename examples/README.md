# Examples

Code that Shorwatch flags, and the reports it produces. Nothing here is meant
to be compiled or run: these files exist to be scanned.

| Folder | What it shows |
|---|---|
| [`algorithms/`](algorithms/) | One minimal file per detected algorithm (RSA, DH, ECDH, ECDSA, EdDSA, DSA, ElGamal, AES-128, SHA-1, 3DES) plus JWT signatures |
| [`spring-service/`](spring-service/) | A small Spring Boot payments service: an RSA-signed authorization server, a webhook signer whose algorithm comes from `application-prod.yml` through `@Value`, a legacy crypto helper, TLS cipher suites, a class already migrating to hybrid ML-KEM, and partner keys written in Kotlin |
| [`output/`](output/) | The reports for `spring-service/` in every format |

## Try it

From the repository root:

```sh
cargo run --release -- scan examples/spring-service
cargo run --release -- scan examples/algorithms --compact
cargo run --release -- scan examples/spring-service --format sarif --output report.sarif
```

## What to look at in the reports

- `AuthorizationServerConfig.java` is reported twice: the RSA key pair
  (`jvm.jca.rsa`) and the RSA JWK built from it (`jvm.nimbus.jose-rsa`).
- `TokenSigner.java` reads its algorithm from configuration. It is `HS256` by
  default but `ES256` in the `prod` profile, so the `JWSAlgorithm.parse(...)`
  call is reported, and so is the config key itself.
- `LegacyCrypto.java`: SHA-1, 3DES through a constant, and AES-128. Only the
  AES-128 finding carries an automatic fix (`128` → `256`).
- `HybridKeyExchange.java` uses X25519 next to ML-KEM: reported as
  **in transition**, not vulnerable.
- `PartnerKeys.kt` is Kotlin: the same JVM rules apply. The EC key generated
  inside `apply { initialize(...) }` and the `ES384` member import are found
  like their Java equivalents.
- `application.yml`: an RS256 resource server and a TLS 1.2 ECDHE suite.

Regenerate `output/` after changing rules or examples:

```sh
for f in sarif cbom json markdown; do
  ext=$f; [ $f = markdown ] && ext=md; [ $f = cbom ] && ext=cdx.json
  cargo run -q -- scan examples/spring-service --format $f --output examples/output/report.$ext
done
cargo run -q -- scan examples/spring-service --output examples/output/report.txt
```
