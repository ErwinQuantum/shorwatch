# ECDSA in JWT and JOSE

`ES256`, `ES384` and `ES512` tokens are forgeable once someone can run Shor's
algorithm on the issuer's public key.

## What it is

ECDSA over the NIST curves P-256, P-384 and P-521 (`ES256`, `ES384`, `ES512`),
plus `ES256K` on secp256k1. It is the usual choice when RS256 tokens feel too
big: a signature is 64 to 132 bytes, against 256 or more for RSA.

## Why it matters

The verifying key sits in a JWKS endpoint for anyone to download. Shor's
algorithm computes the private key from it. An attacker then signs valid
tokens for any user, with any claims. The same reasoning as for
[ECDSA in general](ecdsa.md), with one JWT-specific aggravation: tokens are
accepted automatically, by many services, with no human looking.

## How urgent

The token is short-lived; the key is not. A token that has already expired is
harmless, but the issuer key that signs next year's tokens can be attacked, and
issuer keys tend to live a long time.

The action item is not to rotate tomorrow. It is to make sure that when a
post-quantum algorithm is available in your stack, switching is a
configuration change and not a rewrite.

Severity: **High**. Shorwatch never offers an automatic fix for this class.

## What to do

Plan the move to ML-DSA (FIPS 204) token signatures, defined for JOSE in
RFC 9964 as `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87`. The RFC is recent and
the algorithms are optional to implement, so check that your JWT library
supports them before you plan around it.

- Make verifiers algorithm-agile now: several keys in the JWKS, accepted
  algorithms pinned per key, so issuers can switch without a flag day where
  every consumer must upgrade at once.
- Check size limits. ML-DSA signatures run from about 2.4 to 4.6 KB, against
  64 to 132 bytes for ECDSA. Cookies (4 KB), HTTP header limits in proxies
  and Authorization headers are where this tends to break.
- Consider reference tokens (opaque IDs checked against the issuer) where size
  is a real problem.

## Where Shorwatch finds it

- **Nimbus JOSE+JWT:** the `ES256`, `ES256K`, `ES384` and `ES512` algorithm
  constants, `ECDSASigner` and `ECDSAVerifier`.
- **jose4j:** the `ECDSA_USING_*` constants of `AlgorithmIdentifiers`, and
  the `ES*` names passed to `setAlgorithmHeaderValue`.
- **fusionauth-jwt:** the `ES*` values of `Algorithm`, and the `ECSigner` and
  `ECVerifier` factories.
- **jjwt:** `ES256`, `ES384` and `ES512` in `Jwts.SIG` and `SignatureAlgorithm`.
- **auth0 java-jwt:** `Algorithm.ECDSA256`, `ECDSA256K`, `ECDSA384` and
  `ECDSA512`.
- **Spring Security:** the `ES*` constants in `SignatureAlgorithm` and
  `JwsAlgorithms`.
- **Tink:** the `JWT_ES*` key templates.
- **Configuration:** keys such as `alg`, `algorithm(s)`, `signing-algorithm(s)`
  and `signature-algorithm(s)` set to an `ES*` value, and
  `spring.security.oauth2.resourceserver.jwt.jws-algorithms` in Spring Boot.

An injected value (`@Value("${jwt.alg}")`) is followed from the configuration
key to where it is used. You may fix one without the other.

## False positives and limits

- Shorwatch can't see key lifetimes or which tokens carry long-lived trust.
  A short-lived internal token and a public issuer get the same finding.
- A JWT signing algorithm set at runtime, or read from a source other than
  source code and configuration files, is not visible to it.
- Only the libraries above are read. jose4j and fusionauth-jwt appear in the
  dependency inventory when a build file declares them, but their code is not
  scanned for algorithms.
- Configuration values are matched exactly and JOSE names are case-sensitive,
  so `es256` is not reported. Spring Boot's `jws-algorithms` takes `ES256`,
  `ES384` and `ES512`.
- Parsing an EC key from a JWK (`ECKey.parse`) is not reported by itself.
  Building or using one is, and the key shows up as [generic EC](ec.md).

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9964, ML-DSA for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9964)
- [RFC 7518, JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)