# AES-128 in JWE

A JWE that uses a 128-bit AES key has the same mild Grover margin loss as
[AES-128](aes-128.md), with a JOSE-specific catch: you can't change it
unilaterally.

## What it is

Encrypted JWTs (JWE) use AES in two places, and both have 128-bit variants:

- Content encryption: `A128GCM` and `A128CBC-HS256`.
- Key wrapping: `A128KW`, `A128GCMKW`, and the combined forms ending in
  `A128KW` (`ECDH-ES+A128KW`, `PBES2-HS256+A128KW`).

`A128CBC-HS256` is not a plain 128-bit scheme: it combines a 128-bit AES key
for encryption with a 128-bit key for the MAC. The AES-128 half is what
Shorwatch flags.

## Why it matters

Grover's algorithm reduces a brute-force search over a 128-bit key from about
2^128 steps to about 2^64, which leaves roughly 64 bits of quantum security.
As with plain AES-128, that is a smaller margin and not a break: Grover
doesn't parallelize well, and NIST still accepts AES-128. The case for the
256-bit variants is strongest when the token payload has to stay confidential
for a long time.

## How urgent

Low. In a JWE, the key-management algorithm is usually the bigger exposure: if
the content key is protected with `RSA-OAEP` or `ECDH-ES`, Shor's algorithm
breaks that long before Grover matters for the AES part (see
[ECDH in JWE](jose-ecdh.md)). Look there first.

Severity: **Low**.

## What to do

Use the 256-bit variants: `A256GCM` (or `A256CBC-HS512`) for content
encryption, and `A256KW` or `A256GCMKW` for key wrapping.

Shorwatch offers no automatic fix. A JWE has two sides, and every consumer must
accept the new algorithm before any producer starts using it, or tokens
get rejected. The key-wrapping variants also need 256-bit keys, so the keys
change too.

A safe order: first update consumers to accept both, then switch producers,
then drop the old algorithm.

## Where Shorwatch finds it

- **Nimbus JOSE+JWT:** the `EncryptionMethod` and `JWEAlgorithm` constants
  with a 128-bit AES key, and the same names read with
  `EncryptionMethod.parse("A128GCM")` or `JWEAlgorithm.parse("A128KW")`.
- **jjwt 0.12 and later:** the `Jwts.ENC` and `Jwts.KEY` constants.
- **Configuration:** `alg` and `algorithm(s)` keys (key management) and `enc`
  keys (content encryption) set to an exact 128-bit name, for settings you
  define yourself.

## False positives and limits

- Shorwatch matches constants, classes and configuration values, not strings
  in code. A header value written as a plain `"A128GCM"` literal is not
  reported (`EncryptionMethod.parse("A128GCM")` is).
- A value like `ECDH-ES+A128KW` gives two findings: the key agreement
  ([ECDH in JWE](jose-ecdh.md)) and the 128-bit key wrap on this page. Each has
  its own fix.
- Only Nimbus and jjwt have rules for JWE. jose4j and fusionauth-jwt appear in
  the dependency inventory when a build file declares them, but their code is
  not scanned.
- Older jjwt versions (before 0.12) use a different API and are not covered.
- Configuration values are matched exactly, and JOSE names are
  case-sensitive. A key named something other than `alg`, `algorithm` or
  `enc` is not read.

## References

- [RFC 7518, JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)
- [NSA, CNSA 2.0 algorithms](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)