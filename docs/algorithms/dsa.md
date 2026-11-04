# DSA

DSA signatures are forgeable with Shor's algorithm, and DSA was on its way
out before quantum computers entered the picture.

## What it is

The Digital Signature Algorithm, from the 1990s. It signs with a key pair based
on the finite-field discrete logarithm problem, in the same family as
Diffie-Hellman and ElGamal. You will mostly meet it in old SSH keys
(`ssh-dss`), legacy PGP keys and certificates from that era.

## Why it matters

Two separate reasons, and the first would be enough.

1. It rests on the discrete logarithm problem, which Shor's algorithm solves.
   A quantum attacker derives the private key from the public one and signs
   whatever they like.
2. It was already considered obsolete. FIPS 186-5 (2023) no longer approves DSA
   for generating new signatures, and OpenSSH disabled `ssh-dss` by default
   years ago. The SSH form, `ssh-dss`, is limited to 1024-bit keys, which is
   weak even against classical attackers.

## How urgent

High, like the other public-key findings, with an extra push: the classical
reasons are real today and the quantum one comes on top.

NIST IR 8547's 2030/2035 timeline lists ECDSA, EdDSA and RSA but not DSA, so
there is no quantum deadline to wait for. If you still have DSA keys, replace
them now.

## What to do

Move signatures to ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) if you want a
conservative hash-based scheme. Shorwatch offers no automatic fix: replacing a
signature scheme changes keys, formats and verifiers.

If you need something today and your peers don't speak post-quantum yet,
Ed25519 or ECDSA are a reasonable stopover: they fix the classical weakness,
but they are still quantum-vulnerable, so you will migrate them again later.
Go straight to a post-quantum scheme wherever your peers allow it.

Keep DSA only to *verify* legacy signatures, and plan to re-sign anything
long-lived with the new scheme.

## Where Shorwatch finds it

- **JCA:** `Signature` with a DSA name (`DSA`, `SHA256withDSA`,
  `NONEwithDSA`, `...inP1363Format`, and the older aliases `DSS`,
  `DSAWithSHA1`, `RawDSA` and the signature OID), `KeyPairGenerator`,
  `KeyFactory` and `AlgorithmParameterGenerator` with `DSA`, and
  `DSAParameterSpec` / `DSAPublicKeySpec` / `DSAPrivateKeySpec`.
- **BouncyCastle:** `DSASigner`, `DSAKeyPairGenerator` and
  `DSAParametersGenerator`; with bcpkix, the certificate signer builders
  (`SHA256withDSA`, `BcDSAContentSignerBuilder`).
- **OpenPGP:** the DSA public key tag.
- **JSch and Apache SSHD:** `ssh-dss` in an algorithm list, `KeyPair.DSA`,
  `BuiltinSignatures.dsa*` and `KeyUtils.DSS_ALGORITHM`.
- **XML Signature and OpenSAML:** `SignatureMethod.DSA_*` and the
  `ALGO_ID_SIGNATURE_DSA*` constants.
- **Key material:** DSA keys and certificates in PEM and DER files, Java
  keystores and PKCS#12, and `ssh-dss` keys (`authorized_keys`, `.pub`
  files). The finding names the key size. Encrypted content is skipped, since
  Shorwatch has no password.

## False positives and limits

- A DSA entry in a *verification* path (reading old archives) is lower risk
  than one that signs. Shorwatch reports both.
- An SSH configuration that lists `ssh-dss` among the algorithms it accepts is
  reported because it is offered, even if no peer ever uses it.
- The bare SSH constants `HostKey.SSHDSS` (JSch) and `KeyPairProvider.SSH_DSS`
  (Apache SSHD) are not reported by themselves. RSA has the same gap.
- A DSA key that BouncyCastle only describes (`DSAParameters`,
  `DSAPublicKeyParameters`) is not reported until something signs, verifies or
  generates a key with it.
- A certificate signed with `SHA1withDSA` over a key of another type is not
  matched by this rule.

## References

- [FIPS 186-5, Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547, Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/final)