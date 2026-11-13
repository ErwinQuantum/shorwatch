# SHA-1

SHA-1 is broken for signatures and certificates already. Quantum computers are
the smaller part of the story here.

## What it is

A 160-bit hash function from 1995. It was everywhere: certificate
signatures, Git object names, code signing, XML Signature, HMAC. Shorwatch
reports it when it is used as a hash or inside a signature (`SHA1withRSA`,
`SHA-1` digests, a SHA-1 certificate signature).

## Why it matters

- **Collisions are practical.** The first SHA-1 collision was published in
  2017 (SHAttered). In 2020 a chosen-prefix collision made attacks on
  certificates and signatures affordable for a motivated attacker. A hash
  that can't resist collisions can't protect a signature.
- **Grover narrows the rest.** Finding an input for a given SHA-1 output
  (a preimage) is still out of reach for classical computers, about 2^160
  work. Grover's algorithm brings that to about 2^80, thin compared with
  SHA-256's 2^128. But the collision break is the reason to move today, not
  Grover.

NIST will retire SHA-1 completely by 31 December 2030.

## How urgent

Medium, and about now, not about quantum. If SHA-1 protects a signature, a
certificate or an integrity check someone can attack, it is a problem today.

Severity: **Medium**.

## What Shorwatch does not report

Shorwatch does not flag every use of SHA-1:

- **HMAC-SHA1** is not reported. HMAC doesn't rely on collision resistance,
  and it isn't broken by the known attacks.
- **PBKDF2 with SHA-1** is not reported.
- **OAEP with SHA-1** is not reported.
- The SHA-1 signature of a **self-signed certificate** is not reported:
  nothing verifies it.

These may still be worth moving off SHA-1, but they aren't the same
severity, and flagging them would bury the findings that matter.

## What to do

Use SHA-256 or SHA-384 (SHA-2), or SHA3-256.

Shorwatch offers no automatic fix. Hashes are stored, compared and sent to
other systems, so changing the algorithm in one place silently breaks values
that already exist and the peers that expect them. Migrate the data and its
consumers together: a new column or field for the new hash, dual-write,
verify, then drop the old one.

## Where Shorwatch finds it

- **.NET:** `SHA1.Create`, `SHA1.HashData`, `SHA1Managed`,
  `SHA1CryptoServiceProvider`, `SHA1Cng`, `HashAlgorithmName.SHA1` and the name
  "SHA1" given to `HashAlgorithm.Create`. `HMACSHA1` is not reported.
- **JCA:** `MessageDigest.getInstance` with `SHA`, `SHA-1`, `SHA1` or the
  digest OID, and `Signature.getInstance` with any `SHA1with…` name, the older
  aliases (`DSAWithSHA1`, `SHAwithDSA`, `SHA1/DSA`) and the SHA-1 signature
  OIDs.
- **BouncyCastle:** `SHA1Digest`, and `JcaContentSignerBuilder` with a
  `SHA1with…` name for certificates.
- **BouncyCastle for .NET:** `Sha1Digest`, and a SHA-1 name given to
  `DigestUtilities.GetDigest` or `SignerUtilities.GetSigner`.
- **OpenPGP:** the `SHA1` hash algorithm tag.
- **Commons Codec and Guava:** `DigestUtils.sha1`, `sha1Hex`, `getSha1Digest`,
  their deprecated names (`sha`, `shaHex`, `getShaDigest`),
  `MessageDigestAlgorithms.SHA_1` and `Hashing.sha1()`.
- **Spring Security:** `new MessageDigestPasswordEncoder("SHA-1")` and
  `LdapShaPasswordEncoder` (the LDAP `{SHA}` scheme).
- **XML Signature and OpenSAML:** the SHA-1 digest and signature constants,
  including the plain `RSA` and `DSA` signature ids, which are SHA-1 based,
  and the same algorithms written as URIs
  (`http://www.w3.org/2000/09/xmldsig#rsa-sha1`, `#sha1`).
- **Key material:** certificates whose signature uses SHA-1.

## False positives and limits

- In .NET, `HashAlgorithmName.SHA1` is also what PBKDF2, HKDF and HMAC take.
  It is skipped when it is an argument of `Rfc2898DeriveBytes` (the constructor or
  `Pbkdf2`), `HmacData`, `CreateHMAC` or `HKDF`'s methods; `HMAC.HashData` shares its
  name with plain hashing, so an HMAC computed that way is reported.
- Shorwatch can't tell a SHA-1 used as a fingerprint or cache key from one
  protecting a signature. If nothing an attacker controls depends on it, the
  finding is lower priority.
- A digest name read from configuration at runtime is not reported. XML
  Signature algorithms written as URIs in a `.xml` file are not read either,
  only the ones written as strings in code.
- The `#hmac-sha1` URI is deliberately not matched, for the same reason as
  HMAC-SHA1 in the JCA.
- A `SHA1withRSA` or `SHA1withDSA` signature gives two findings: SHA-1 and the
  public-key algorithm ([RSA](rsa.md), [DSA](dsa.md)). Each has its own fix.
- Spring Security's `StandardPasswordEncoder` and the other encoders that do
  not name SHA-1 are not reported. Password hashing with a plain digest is a
  problem of its own, whatever the digest.

## References

- [NIST retires SHA-1](https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm)
- [FIPS 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)