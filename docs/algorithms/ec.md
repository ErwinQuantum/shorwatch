# Elliptic-curve keys (generic)

An elliptic-curve key is broken by Shor's algorithm, whichever job it does.
This finding exists because the code doesn't say which job.

## What it is

Elliptic-curve cryptography does public-key work with much smaller keys than
RSA: a 256-bit curve key gives roughly the classical security of a 3072-bit RSA
key. The same kind of key pair can do key agreement (ECDH) or signatures
(ECDSA), so APIs often just ask for `"EC"` and a curve name.

## Why it matters

The security rests on the elliptic-curve discrete logarithm problem, and
Shor's algorithm solves it. A quantum attacker computes the private key from
the public one. Smaller keys are in fact a disadvantage here: at a comparable
classical strength, published estimates say breaking an elliptic-curve key
needs a smaller quantum computer than breaking RSA. Estimates for both keep
changing, so don't read the gap as permanent. Either way, both fall.

## Why it gets its own finding

`KeyPairGenerator.getInstance("EC")` creates a key without saying what it will
be used for. Shorwatch can't call it ECDH or ECDSA from that line alone, and
guessing would be wrong some of the time. So it reports "an EC key exists" and
leaves the specific findings ([ECDH](ecdh.md), [ECDSA](ecdsa.md)) to the calls
where the operation actually happens.

If a file shows both a generic and a specific finding, they are the same
problem seen from two angles. Replacing the key pair and its operation
resolves both.

## How urgent

Shorwatch reports it as high severity. How soon depends on the use, which is
the reason to find out:

- Key agreement or encryption: urgent (*harvest now, decrypt later*).
- Signatures: urgent for long-lived keys, less for short-lived ones.

## What to do

Find out what the key is for, then follow that page. In short: ML-KEM
(FIPS 203), ideally as a hybrid such as `X25519MLKEM768`, for key agreement;
ML-DSA (FIPS 204), possibly as a composite with ECDSA, for signatures. Either
way it is a protocol migration, so Shorwatch offers no automatic fix.

## Where Shorwatch finds it

- **JCA:** `KeyPairGenerator`, `KeyFactory` and `AlgorithmParameters` with
  `"EC"`, and the curve specs `ECGenParameterSpec`, `ECParameterSpec`,
  `ECPublicKeySpec` and `ECPrivateKeySpec`.
- **BouncyCastle:** `ECKeyPairGenerator`.
- **BouncyCastle for .NET:** `ECKeyPairGenerator`, and `"EC"` given to
  `GeneratorUtilities.GetKeyPairGenerator`.
- **JWT libraries:** Nimbus `ECKeyGenerator` and `ECKey.Builder`, and jjwt's
  `Jwks.CRV.P256`, `P384` and `P521`. An EC JWK can sign (ES256) or agree on
  keys (ECDH-ES), hence the generic finding.
- **Microsoft.IdentityModel (.NET):** the `EC` JWK key type
  (`JsonWebAlgorithmsKeyTypes.EllipticCurve`).
- **Cloud KMS:** AWS `KeySpec.ECC_*` (and `SM2`), Azure Key Vault `KeyType.EC*`,
  `KeyCurveName.P_*` and `CreateEcKeyOptions`.
- **Android Keystore:** `KeyProperties.KEY_ALGORITHM_EC`.
- **Apache SSHD:** `KeyUtils.EC_ALGORITHM` and a host key provider set to `EC`.
- **Key material:** EC keys and certificates in PEM and DER files, Java
  keystores and PKCS#12; the finding names the curve. SSH keys of this type
  (`ecdsa-sha2-*`) are reported as [ECDSA](ecdsa.md). Encrypted content is
  skipped, since Shorwatch has no password.

## False positives and limits

- Shorwatch reports that an EC key or curve exists, not what it is used for.
  Parameter specs such as `ECGenParameterSpec` are reported where they are
  built, even before a key exists.
- Where the file also performs the ECDH or ECDSA operation, that call gets its
  own finding as well.
- Code that only names a curve is not reported: BouncyCastle's
  `ECNamedCurveTable`, `CustomNamedCurves` and `ECDomainParameters`, or
  Nimbus' `Curve.P_256` on its own. The operation that uses it is.
- The curve is not judged. `secp256r1` and `secp521r1` are the same finding;
  none of them is safer against Shor's algorithm.

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST IR 8547, Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/final)
- [Roetteler et al., Quantum resource estimates for computing elliptic curve discrete logarithms](https://www.microsoft.com/en-us/research/publication/quantum-resource-estimates-computing-elliptic-curve-discrete-logarithms/)