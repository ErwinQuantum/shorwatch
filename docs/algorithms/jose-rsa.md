# RSA in JWT and JOSE

A JWT signed with `RS256`, `PS256` or their siblings is only as safe as the RSA
key behind it, and that key doesn't survive Shor's algorithm.

## What it is

JOSE is the family of standards behind JWT, JWS (signed tokens) and JWE
(encrypted tokens). Its algorithm names are strings in the token header:

- Signatures: `RS256`, `RS384`, `RS512` (PKCS#1 v1.5) and `PS256`, `PS384`,
  `PS512` (RSA-PSS).
- Encryption: `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5`.

Identity providers publish the verifying keys as a JWKS (JSON Web Key Set)
at a well-known URL, so that anybody can check a token.

## Why it matters

The JWKS is public by design, and Shor's algorithm turns a public RSA key
into a private one. With the private key an attacker can mint tokens that
every verifier accepts: any user, any role, any expiry. For encrypted tokens
the problem is the usual one: a recorded JWE can be opened later.

Moving to a bigger key does not help. RSA-4096 falls to Shor's algorithm just
like RSA-2048.

The severity comes from the amplification. One signing key stands behind every
token an issuer produces, so breaking it is breaking authentication for the
whole system.

## How urgent

Two things to separate:

- **The signing key and the verifiers.** The token itself is usually
  short-lived, so old tokens aren't the issue. The key is. If the issuer's
  RSA key lives for years, and it usually does, it has to move before a
  quantum computer able to break it exists.
- **Encrypted tokens with long-lived content.** These are exposed to
  *harvest now, decrypt later*, like any other encrypted data. Putting
  long-lived secrets in a JWE is a bad idea whatever the algorithm.

NIST IR 8547 deprecates RSA after 2030 and disallows it after 2035.

Severity: **High**. Shorwatch never offers an automatic fix for this class.

## What to do

Plan the move to post-quantum JOSE algorithms. For signatures, ML-DSA
(FIPS 204) is standardized for JOSE in RFC 9964 as `ML-DSA-44`, `ML-DSA-65` and
`ML-DSA-87`. Check that your JWT library supports them first: the RFC is
recent and the algorithms are optional to implement.

RFC 9964 covers signatures only and defines nothing for encryption. For
encrypted tokens the target is ML-KEM (FIPS 203); check where the IETF work on
ML-KEM in JOSE stands before committing to a design.

You can start before the libraries catch up, by making the system
algorithm-agile:

- Publish several keys in the JWKS and select them by `kid`.
- Pin the accepted algorithm per key on the verifier side, never trusting
  the `alg` header alone.
- Keep token size in mind: an ML-DSA-44 signature is around 2.4 KB against
  256 bytes for `RS256` with a 2048-bit key. Proxies, cookies and header
  limits may complain.

Remove `RSA1_5` today regardless of quantum. It is vulnerable to padding
oracle attacks (Bleichenbacher).

HMAC-based tokens (`HS256`) are not part of this finding: symmetric MACs with
a 256-bit key are fine against quantum attackers, though they have their own
key-distribution problems.

## Where Shorwatch finds it

- **Nimbus JOSE+JWT:** the `RS*` and `PS*` signature constants, the `RSA1_5`
  and `RSA-OAEP*` encryption constants, `RSASSASigner` / `RSASSAVerifier`,
  `RSAEncrypter` / `RSADecrypter`, `RSAKeyGenerator`, `RSAKey.Builder`,
  `RSAKey.parse` / `RSAKey.load` and the RSA algorithm families.
- **jose4j:** the `RSA_USING_SHA*` and `RSA_PSS_USING_SHA*` constants of
  `AlgorithmIdentifiers`, the `RSA1_5` and `RSA_OAEP*` constants of
  `KeyManagementAlgorithmIdentifiers`, the same names passed to
  `setAlgorithmHeaderValue`, `RsaJwkGenerator` and `RsaJsonWebKey`.
- **fusionauth-jwt:** the `RS*` and `PS*` values of `Algorithm`, and the
  `RSASigner`, `RSAVerifier`, `RSAPSSSigner` and `RSAPSSVerifier` factories.
- **jjwt:** the `RS*`, `PS*` and `RSA*` constants in `Jwts.SIG`, `Jwts.KEY`
  and `SignatureAlgorithm`, and `SignatureAlgorithm.forName`.
- **auth0 java-jwt:** `Algorithm.RSA256`, `RSA384` and `RSA512` (the `PS*`
  algorithms are not covered).
- **Spring Security:** the `RS*` and `PS*` constants,
  `NimbusJwtDecoder.withPublicKey` (plain and reactive), and the decoders that
  name no algorithm and so verify RS256 (see below).
- **Microsoft.IdentityModel (.NET):** `SecurityAlgorithms.RsaSha256`, `RsaSha384`,
  `RsaSha512`, the `RsaSsaPss*` constants, the `RsaPKCS1` and `RsaOAEP` key-wrap
  constants (and the XML Signature URI forms), `RsaSecurityKey`, the
  `RSA` JWK key type, and `SigningCredentials` / `EncryptingCredentials` given
  an `RS*`, `PS*` or `RSA-OAEP` name.
- **Tink:** the `JWT_RS*` and `JWT_PS*` key templates.
- **Configuration:** (in Spring `application.yml` / `.properties` and in .NET
  `appsettings.json`) `alg`, `algorithm(s)`, `signing-algorithm(s)` and
  `signature-algorithm(s)` keys set to an exact `RS*` / `PS*` name, and in
  Spring Boot `jws-algorithms` and `public-key-location` (Spring Boot only
  supports RSA keys there), and `jwk-set-uri` when no `jws-algorithms` is set.
  In Quarkus, `mp.jwt.verify.publickey` and its `.location` (and the decryption
  key) when no `.algorithm` names another: Quarkus's guide documents RS256 and
  RSA-OAEP as their defaults.

### RS256 as a default

Spring Security's documentation says that, by default, `NimbusJwtDecoder` "will
only trust and verify tokens using `RS256`". Shorwatch reports the builders
that rely on that default: `NimbusJwtDecoder.withJwkSetUri(...)` and
`withJwkSource(...)` (plain and reactive), and the Spring Boot property
`spring.security.oauth2.resourceserver.jwt.jwk-set-uri`. The report is skipped
when the chain goes on to choose: `.jwsAlgorithm(...)`, `.jwsAlgorithms(...)`
or `.jwtProcessorCustomizer(...)`, and, in a configuration file, when the same
file sets `jws-algorithms`. What the code chooses is reported on its own
(`SignatureAlgorithm.ES256` is an ECDSA finding).

## False positives and limits

- Shorwatch can't see key lifetimes or which tokens carry long-lived trust.
  A short-lived internal token and a public issuer get the same finding.
- Shorwatch matches constants and configuration keys, not strings in code. A
  header value written as a plain `"RS256"` literal is not reported
  (`JWSAlgorithm.parse("RS256")` and `SignatureAlgorithm.forName("RS256")` are).
- Only the libraries above are read. jose4j and fusionauth-jwt appear in the
  dependency inventory when a build file declares them, but their code is not
  scanned for algorithms.
- The RS256 default is read from the call chain and from one file. A builder
  kept in a variable and configured later (`b.jwsAlgorithm(...)`) is still
  reported as the default, and so is a `jwk-set-uri` whose `jws-algorithms`
  lives in another file (`application-prod.yml`).
- Micronaut's JWT settings and Quarkus's TLS cipher suites are not read: their
  property names are not verified yet.
- `NimbusJwtDecoder.withIssuerLocation(...)`, `JwtDecoders.fromIssuerLocation`
  and the `issuer-uri` property are not reported: the first takes the
  algorithms from the issuer's JWK Set, and Spring's documentation does not
  say what the others default to.
- Config values are matched exactly. JOSE names are case-sensitive, so `rs256`
  is not reported.
- Parsing an RSA key from a JWK (`RSAKey.parse`, `RSAKey.load`) is not
  reported by itself, only building or using it is.

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)
- [RFC 9964, ML-DSA for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9964)
- [RFC 7518, JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)