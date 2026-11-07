# EdDSA in JWT and JOSE

Tokens signed with `EdDSA` (Ed25519 or Ed448) are forgeable with Shor's
algorithm, like any other elliptic-curve signature.

## What it is

RFC 8037 added Edwards curves to JOSE: the `EdDSA` algorithm and the `OKP`
key type with curves `Ed25519` and `Ed448`. It is attractive for tokens
because it is fast, deterministic and has small signatures (64 bytes for
Ed25519).

## Why it matters

The security still rests on the elliptic-curve discrete logarithm problem. The
JWK that verifies the tokens is public, so a quantum attacker derives the
signing key from it and mints valid tokens. What makes EdDSA nicer than ECDSA
(no bad-nonce failure, simpler implementation) is about classical
attackers and doesn't change this.

## How urgent

Same logic as [ECDSA in JOSE](jose-ecdsa.md). A token that has already expired
is harmless; the issuer key that signs next year's tokens is what can be
attacked. The urgency is how long that key lives and how easily you could
switch it.

Severity: **High**. Shorwatch never offers an automatic fix for this class.

## What to do

Plan the move to ML-DSA (FIPS 204) token signatures, standardized for JOSE in
RFC 9964 (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`). The RFC is recent and the
algorithms are optional to implement, so check that your JWT library supports
them before you plan around it.

The size jump is the main operational cost: an ML-DSA-44 signature is about
2.4 KB against 64 bytes for Ed25519, nearly forty times more. Check headers,
cookies and proxy limits.

As with the other JOSE algorithms, make verifiers algorithm-agile first: keys
in the JWKS selected by `kid`, accepted algorithms pinned per key. That turns
the later switch into a rollout instead of a flag day.

## Where Shorwatch finds it

- **jose4j:** `AlgorithmIdentifiers.EDDSA`, and `"EdDSA"` passed to
  `setAlgorithmHeaderValue`.
- **fusionauth-jwt:** the `Ed25519` and `Ed448` values of `Algorithm`, and the
  `EdDSASigner` and `EdDSAVerifier` factories.
- **Nimbus JOSE+JWT:** the `EdDSA`, `Ed25519` and `Ed448` algorithm constants,
  `JWSAlgorithm.parse`, `Ed25519Signer`, `Ed25519Verifier` and the EdDSA
  algorithm family. The `Ed25519` and `Ed448` curves are reported too, so
  creating an Edwards-curve key (`OctetKeyPairGenerator(Curve.Ed25519)`,
  `OctetKeyPair.Builder`) is found through them.
- **jjwt:** `Jwts.SIG.EdDSA` and the `Ed25519` / `Ed448` curve constants.
- **Configuration:** keys such as `alg`, `algorithm(s)`, `signing-algorithm(s)`
  and `signature-algorithm(s)` set to `EdDSA`, `Ed25519` or `Ed448`.

The X25519 and X448 curves of the same key type are key agreement, not
signatures: they are on the [ECDH in JOSE](jose-ecdh.md) page.

## False positives and limits

- Shorwatch can't see key lifetimes or which tokens carry long-lived trust.
  A short-lived internal token and a public issuer get the same finding.
- Shorwatch matches constants and configuration keys, not strings in code. A
  header value written as a plain `"EdDSA"` literal is not reported
  (`JWSAlgorithm.parse("EdDSA")` is).
- Nimbus, jjwt, jose4j and fusionauth-jwt have EdDSA rules. There is none for
  auth0 java-jwt, Spring Security or Tink.
- Configuration values are matched exactly, and JOSE names are
  case-sensitive: `eddsa` is not reported.
- Parsing a key from a JWK (`OctetKeyPair.parse`) is not reported by itself.

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9964, ML-DSA for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9964)
- [RFC 8037, CFRG ECDH and signatures in JOSE](https://www.rfc-editor.org/rfc/rfc8037)