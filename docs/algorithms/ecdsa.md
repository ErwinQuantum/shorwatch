# ECDSA

ECDSA signatures are forgeable with Shor's algorithm. The risk concentrates in
keys that live a long time.

## What it is

The elliptic-curve signature algorithm, the usual choice when RSA is too large
or slow: TLS certificates, code signing, JWTs (`ES256`), blockchain keys and
SSH (`ecdsa-sha2-nistp256`).

## Why it matters

A quantum attacker with Shor's algorithm computes the private key from the
public key and can sign anything as the owner. Public keys are public by
design: they sit in certificates, JWKS endpoints and key servers.

## How urgent

Signatures are different from encryption. A forged signature is only useful
when someone checks it, so for short-lived uses (a session, a token that
expires in minutes) there is no *harvest now, decrypt later* version of this
attack: a signature you verified today does not become a problem later. The
urgency is the lifetime of the key, and how long a signature must stay
trustworthy.

- **Very exposed:** root and intermediate CA keys, firmware and boot signing
  keys, code-signing identities, signing keys in long-lived JWKS endpoints,
  anything embedded in a device you can't update.
- **Also exposed:** signed documents, contracts and timestamps that must stay
  verifiable for decades. Once ECDSA can be forged, an old signature no longer
  proves it is old.
- **Less exposed:** keys that rotate every few months, for sessions that end.

A device shipped today with an ECDSA root of trust will still be in the field
when a quantum computer able to break it exists. That is why firmware signing
is usually the first place to look.

NIST IR 8547 deprecates ECDSA after 2030 and disallows it after 2035.

Severity: **High**. Shorwatch never offers an automatic fix for this class.
Replacing a signature scheme changes formats, sizes and trust chains.

## What to do

Migrate signatures to ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a
conservative hash-based scheme is preferred, for example for firmware roots.
Expect bigger everything: an ML-DSA-65 signature is 3,309 bytes and its public
key 1,952, against about 64 bytes each for ECDSA P-256 in raw form. Check
certificate sizes, wire formats, storage and any size limits on the way.

During the transition, dual (composite) signatures carry ECDSA and ML-DSA
together so existing verifiers keep working.

## Where Shorwatch finds it

- **JCA:** `Signature` with `ECDSA`, `SHA256withECDSA` and the other
  `...withECDSA` names (also `...inP1363Format`, BouncyCastle's `PLAIN-` and
  `CVC-` encodings and the deterministic `ECDDSA`), the ecdsa-with-SHA1/2xx
  OIDs the JDK accepts as names, and `KeyPairGenerator` / `KeyFactory` with
  `ECDSA` (BouncyCastle registers that name).
- **BouncyCastle:** `ECDSASigner`; with bcpkix, the certificate signer builders
  (`SHA256withECDSA`, `BcECContentSignerBuilder`).
- **BouncyCastle for .NET:** `ECDsaSigner`, and an ECDSA name
  (`SHA256withECDSA`...) given to `SignerUtilities.GetSigner`.
- **OpenPGP:** the ECDSA public key tag.
- **.NET:** `ECDsa.Create`, `ECDsaCng`, `ECDsaOpenSsl` and `GetECDsaPublicKey` /
  `GetECDsaPrivateKey` on a certificate.
- **JSch and Apache SSHD:** `ecdsa-sha2-nistp*` in an algorithm list, the
  `HostKey.ECDSA*` and `KeyPairProvider.ECDSA_SHA2_NISTP*` key type constants,
  `KeyPair.ECDSA` and `BuiltinSignatures.nistp*`.
- **XML Signature and OpenSAML:** the `ECDSA_*` signature method constants.
- **Tink:** the ECDSA templates and parameters.
- **Cloud KMS:** AWS `SigningAlgorithmSpec.ECDSA_*` (and `SM2DSA`), Azure Key
  Vault `ES256`/`ES384`/`ES512`/`ES256K`, and GCP `EC_SIGN_*` algorithms.
- **Key material:** SSH ECDSA public keys (`ecdsa-sha2-*`). Other
  elliptic-curve keys and certificates in PEM, DER and keystore files are
  reported as [generic EC](ec.md).

JWT uses are on [their own page](jose-ecdsa.md).

## False positives and limits

- A short-lived signing key and a CA root get the same finding. The
  difference in risk is real; Shorwatch can't see key lifetimes in code.
- Shorwatch looks at source, configuration and key files. A certificate loaded
  at runtime from a keystore, an HSM or a load balancer is not visible to it.
- A certificate that was *signed with* ECDSA is not reported for that reason.
  Only its key is (as generic EC), and the SHA-1 case has its own finding.
- Only ECDSA is matched. SM2 signatures (the Chinese elliptic-curve scheme)
  appear in the AWS KMS rule but not in BouncyCastle's `SM2Signer`.

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)