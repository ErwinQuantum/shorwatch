# ElGamal

ElGamal encryption is broken by Shor's algorithm. You mostly meet it in old
OpenPGP keys.

## What it is

A public-key encryption scheme built on the discrete logarithm problem, from
1985. It is Diffie-Hellman turned into an encryption scheme. It never became
common in new protocols, but it survives in OpenPGP, where many long-lived
keys have an ElGamal encryption subkey, and in some legacy BouncyCastle code.

## Why it matters

Same root as [Diffie-Hellman](dh.md) and [DSA](dsa.md): the discrete logarithm
problem, which Shor's algorithm solves. An attacker recovers the private key
from the public one and decrypts everything encrypted to it.

Encryption is the exposed side. A message encrypted to an ElGamal key and
stored or sent somewhere can be recorded today and opened later (harvest now,
decrypt later). OpenPGP keys also last a long time, which makes it worse:
people keep using the same key for a decade.

## How urgent

Urgent for anything that has to stay confidential for years, such as archived
encrypted email or backups encrypted to a PGP key. Less so for new code, since
you probably aren't writing any.

Severity: **High**. Shorwatch never offers an automatic fix for this class.

## What to do

Use ML-KEM (FIPS 203) to establish a key and a symmetric AEAD such as
AES-256-GCM to encrypt the payload under it. That is how public-key encryption
is done post-quantum: the KEM encrypts a key, not the data.

For OpenPGP specifically, follow the post-quantum OpenPGP work (ML-KEM
composite keys) instead of generating new ElGamal subkeys.

Archives you still hold, encrypted to an ElGamal key, can be decrypted and
re-encrypted with a post-quantum scheme while you still control the key. That
protects the copies you keep. A copy someone else already recorded stays
exposed.

## Where Shorwatch finds it

- **JCA:** `Cipher` (`ElGamal`, `ElGamal/None/PKCS1Padding`...),
  `KeyPairGenerator`, `KeyFactory` and `AlgorithmParameterGenerator` with
  `"ElGamal"` (BouncyCastle registers this name in the JCA).
- **BouncyCastle:** `ElGamalEngine`, `ElGamalKeyPairGenerator`,
  `ElGamalParametersGenerator` and `ElGamalParameters` in the lightweight API,
  and `ElGamalParameterSpec` / `ElGamalGenParameterSpec` in the provider API.
- **OpenPGP:** the `ELGAMAL_ENCRYPT` and `ELGAMAL_GENERAL` algorithm
  constants.

## False positives and limits

- Shorwatch does not read OpenPGP key files. An armored key (`.asc`) or a
  keyring (`.gpg`, `pubring`) with an ElGamal subkey is not reported, even if
  it sits in the repository; only code that names ElGamal is. The key
  material reader (X.509, PEM, SSH, keystores) has no ElGamal key type.
- `ElGamalKeyGenerationParameters` and the provider's `ElGamalPublicKeySpec` /
  `ElGamalPrivateKeySpec` are not reported by themselves, only the classes
  that generate keys or encrypt.
- If the same class also uses post-quantum code (an ML-KEM import, an
  `X25519MLKEM768` string), the finding is reported as `in transition`
  instead of `vulnerable`.

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final)
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)