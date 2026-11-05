# EdDSA (Ed25519 and Ed448)

EdDSA signatures are forgeable with Shor's algorithm. The design is good; the
math underneath is the same.

## What it is

A signature scheme on Edwards curves. Ed25519 and Ed448 were built to avoid
the sharp edges of ECDSA: deterministic nonces (a weak random number generator
can't leak the key), simple implementation, fast. SSH, Git signing, minisign,
DNSSEC and many modern protocols use it.

## Why it matters

Its security still rests on the elliptic-curve discrete logarithm problem,
which Shor's algorithm solves. A quantum attacker derives the private key from
the public one and forges signatures. Everything EdDSA improved over ECDSA is
about classical attackers and implementation mistakes; none of it helps here.

## How urgent

Same as [ECDSA](ecdsa.md). For short-lived uses (a session, a token that
expires in minutes) there is no *harvest now, decrypt later* version of this
attack, so the urgency is the lifetime of the key and how long a signature
must stay trustworthy. Long-lived trust anchors, signed documents that must
stay verifiable for decades, and keys on devices you can't update come first.
Session-length keys can wait for the normal migration.

NIST IR 8547 puts EdDSA on the same timeline as ECDSA: deprecated after 2030,
disallowed after 2035. FIPS 186-5 still approves it today.

Severity: **High**. Shorwatch never offers an automatic fix for this class.

## What to do

Migrate signatures to ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) if you want a
conservative hash-based scheme. Be ready for size: an ML-DSA-65 public key is
1,952 bytes and a signature 3,309, against 32 and 64 for Ed25519. That
matters in constrained places such as DNS records, QR codes, cookies and
embedded protocols.

A composite Ed25519 + ML-DSA signature keeps existing verifiers working
during the transition.

## Where Shorwatch finds it

- **JCA:** `Signature` with `Ed25519`, `Ed25519ph`, `Ed25519ctx`, `Ed448`,
  `Ed448ph` or `EdDSA` (and the Ed25519/Ed448 OIDs, which the JDK accepts as
  names); `KeyPairGenerator` and `KeyFactory` with `Ed25519`, `Ed448` or
  `EdDSA`; and `EdECPublicKeySpec` / `EdECPrivateKeySpec`.
- **BouncyCastle:** the `Ed25519` and `Ed448` signers (including the `ctx` and
  `ph` variants) and key pair generators; with bcpkix,
  `JcaContentSignerBuilder("Ed25519")`.
- **OpenPGP:** the EdDSA public key tags (`EDDSA_LEGACY`, `Ed25519`, `Ed448`).
- **JSch and Apache SSHD:** `ssh-ed25519` and `ssh-ed448` in an algorithm
  list, `KeyPair.ED25519`, `BuiltinSignatures.ed25519` and `KeyUtils.EDDSA`.
- **XML Signature:** Santuario's `ALGO_ID_SIGNATURE_EDDSA_*` constants.
- **Tink:** the Ed25519 templates and parameters.
- **GCP KMS:** `EC_SIGN_ED25519`.
- **I2P EdDSA library:** `EdDSAEngine`, still common in SSH libraries.
- **Key material:** Ed25519 and Ed448 keys and certificates in PEM and DER
  files, Java keystores and PKCS#12, and `ssh-ed25519` keys.

The JWT flavour is on [its own page](jose-eddsa.md).

## False positives and limits

- A short-lived signing key and a long-lived root get the same finding.
  Shorwatch can't see key lifetimes in code.
- Shorwatch looks at source, configuration and key files. A key loaded at
  runtime from a keystore or an HSM is not visible to it.
- A certificate that was *signed with* EdDSA is not reported for that reason,
  only its own key is.
- The bare SSH constants (`KeyPairProvider.SSH_ED25519` in Apache SSHD) and
  classes that only describe a key (`Ed25519PrivateKeyParameters`,
  `NamedParameterSpec.ED25519`, I2P's `EdDSAPublicKey`) are not reported by
  themselves. The signer or generator that uses them is.
- OpenPGP key files (`.asc`, `.gpg`) are not read.
- If the same class also uses post-quantum code, the finding is reported as
  `in transition` instead of `vulnerable`.

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)