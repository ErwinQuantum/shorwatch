# ECDH in JWE

Encrypted tokens that use `ECDH-ES` for key agreement can be recorded now and
opened later.

## What it is

A JWE (an encrypted JWT) has two layers. A random content key encrypts the
payload (for example with `A256GCM`), and a key-management algorithm protects
that content key for the recipient. `ECDH-ES`, `ECDH-ES+A128KW`,
`ECDH-ES+A256KW` and `ECDH-1PU` derive it from an elliptic-curve key
agreement with the recipient's public key. The same applies to X25519 and X448
keys in an `OKP` JWK.

For ECDH outside JOSE, see [ECDH, X25519 and X448](ecdh.md).

## Why it matters

Shor's algorithm solves the elliptic-curve discrete logarithm problem. The
token carries the sender's ephemeral public key in its header, and the
recipient's public key is public too. A quantum attacker who recovers either
private key can derive the shared secret, then the content key, and read the
payload. Anyone who recorded the token can do this later (harvest now,
decrypt later).

Tokens that pass through logs, proxies, browsers or third parties are the
most likely to be recorded without anyone intending it.

## How urgent

It depends on how long the content has to stay secret. A JWE carrying a session
nonce that expires in minutes is not the issue. One carrying personal data,
credentials or anything with a long shelf life is.

Shortening a token's lifetime only helps when the payload stops being useful
once the token expires. A recorded token that held personal data is still
readable after it expires.

Severity: **High**. Shorwatch never offers an automatic fix for this class.

## What to do

Move JWE key management to a post-quantum KEM based on ML-KEM (FIPS 203). The
IETF JOSE working group is defining how ML-KEM plugs into JWE, so most
libraries don't offer it yet. Until they do:

- Keep long-lived secrets out of encrypted tokens.
- Keep encrypted tokens short-lived when their content loses value on expiry.
- If both sides already share a secret, symmetric key management (`dir`, or
  `A256KW` with 256-bit keys) is not affected by Shor's algorithm. It needs a
  safe way to distribute the shared key.
- Make sure producers and consumers can change the key-management algorithm
  together. This changes the JWE header, so both sides must move at once or
  accept both for a while.

## Where Shorwatch finds it

- **jose4j:** the `ECDH_ES*` constants of `KeyManagementAlgorithmIdentifiers`,
  and `ECDH-ES*` passed to `setAlgorithmHeaderValue`.
- **Nimbus JOSE+JWT:** the `ECDH_ES*` and `ECDH_1PU*` algorithm constants,
  `JWEAlgorithm.parse("ECDH-ES")`, the `X25519` and `X448` curves,
  `ECDHEncrypter` / `ECDHDecrypter`, `X25519Encrypter` / `X25519Decrypter`,
  and the ECDH algorithm family. The curves make creating an X25519 key
  (`OctetKeyPairGenerator(Curve.X25519)`) show up too.
- **jjwt 0.12 and later:** the `ECDH_ES*` key-management constants and the
  `X25519` / `X448` curve constants.
- **Microsoft.IdentityModel (.NET):** `SecurityAlgorithms.EcdhEs` and the
  `EcdhEsA128kw`, `EcdhEsA192kw` and `EcdhEsA256kw` constants, and
  `EncryptingCredentials` given an `ECDH-ES*` name.
- **Configuration:** `alg` and `algorithm(s)` keys set to an exact `ECDH-ES`,
  `ECDH-1PU` or key-wrapping variant (`ECDH-ES+A256KW`...), for settings you
  define yourself.

## False positives and limits

- Shorwatch matches constants, classes and configuration values, not strings
  in code. A header value written as a plain `"ECDH-ES"` literal is not
  reported (`JWEAlgorithm.parse("ECDH-ES")` is).
- Nimbus, jjwt and jose4j have rules for ECDH in JOSE. fusionauth-jwt has no
  JWE support to scan.
- Older jjwt versions (before 0.12) use a different API and are not covered.
- Configuration values are matched exactly, and JOSE names are
  case-sensitive. A key named something other than `alg` or `algorithm`, such
  as `key-management-algorithm`, is not read.
- The sender's and recipient's key-management settings are separate. Shorwatch
  reports each place that names the algorithm, not whether the two sides
  agree.

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final)
- [RFC 7518, JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [draft-ietf-jose-pqc-kem, PQ KEM for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/)
  (an Internet-Draft, work in progress)