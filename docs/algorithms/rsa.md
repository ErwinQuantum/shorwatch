# RSA

RSA is broken by Shor's algorithm. No key size fixes it.

## What it is

RSA encrypts and signs using a public key that is the product of two large
primes. It has been the default for key transport and signatures for decades:
TLS certificates, code signing, SSH and PGP keys, JWTs, S/MIME.

## Why it matters

Its security is the difficulty of factoring that product. Classical computers
cannot do it for 2048-bit numbers. A quantum computer running Shor's algorithm
can, in polynomial time, and then it has the private key. A 4096-bit key only
makes the machine somewhat bigger, it does not change the outcome.

Published estimates keep falling. A 2025 analysis by Craig Gidney put RSA-2048
within reach of a machine with fewer than a million noisy qubits running for
under a week. His own 2019 estimate with Martin Ekerå was twenty million
qubits. As far as is publicly known, nothing close to that exists today, but
the estimate dropped by roughly a factor of twenty in a few years, which is
why planners don't treat the date as fixed.

## How urgent

It depends on what the key protects.

- **Encryption and key transport:** urgent. Traffic recorded now can be opened
  later (*harvest now, decrypt later*). If the data must stay secret for ten
  years, the clock started when it was sent.
- **Signatures:** urgent for long-lived keys. A root CA, a firmware signing
  key or a JWKS key that lives for years has to be replaced before a quantum
  computer able to break it exists. Signed documents that must stay
  verifiable for decades are exposed too. A signature on a short-lived
  message is not.

NIST IR 8547 deprecates RSA-2048 after 2030 and disallows RSA after 2035.

Severity: **High**. Shorwatch never offers an automatic fix for RSA.

## What to do

This is a protocol migration, not a drop-in swap.

- Key establishment and encryption: ML-KEM (FIPS 203), ideally in a hybrid
  with a classical exchange while peers catch up.
- Signatures: ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) if you prefer a
  hash-based design.
- Mind the sizes. An ML-DSA-65 signature is 3,309 bytes, against 256 for
  RSA-2048. Check column widths, header limits and certificate chains.
- Make code algorithm-agile now: don't hard-code `"RSA"` where a configured
  value would do. It makes the later switch a configuration change.

Changing the algorithm name in the source would not migrate anything, which is
why Shorwatch does not offer a fix.

## Where Shorwatch finds it

- **.NET:** `RSA.Create`, `RSACryptoServiceProvider`, `RSACng`, `RSAOpenSsl`,
  the `RSAEncryptionPadding` and `RSASignaturePadding` values, `GetRSAPublicKey` /
  `GetRSAPrivateKey` on a certificate, and the name "RSA" given to
  `CryptoConfig.CreateFromName`.
- **JCA:** `KeyPairGenerator`, `KeyFactory`, `Cipher` and `Signature` with an
  RSA name (`RSA`, `RSASSA-PSS`, `RSA/ECB/OAEP...`, `SHA256withRSA`...), and
  `RSAKeyGenParameterSpec`.
- **BouncyCastle:** the RSA engines, `RSAKeyPairGenerator` and
  `RSADigestSigner`; with bcpkix, the certificate signer builders
  (`JcaContentSignerBuilder("SHA256withRSA")`).
- **OpenPGP, JSch, Apache SSHD:** RSA key types, the `ssh-rsa` and
  `rsa-sha2-*` algorithm names, and the `HostKey.SSHRSA` and
  `KeyPairProvider.SSH_RSA` constants.
- **XML Signature and OpenSAML:** the RSA signature and key-transport
  constants.
- **Tink and the cloud KMS clients** (AWS, Azure, GCP), **Android Keystore**
  and **Spring Security**: RSA key specs, templates and encryptors.
- **Configuration:** Spring Cloud Config's `encrypt.rsa.*` and
  `encrypt.key-store.location`.
- **Key material:** RSA keys and certificates in PEM and DER files, Java
  keystores, PKCS#12 and SSH keys. Encrypted content (a password-protected
  PKCS#12 or private key) is skipped, since Shorwatch has no password.

JWT uses of RSA have their own page: [RSA in JOSE](jose-rsa.md).

## False positives and limits

- An RSA key that only *verifies* old signatures during a migration is not the
  same risk as one that signs new ones. Shorwatch cannot tell them apart.
- A certificate that your code merely trusts (a CA in a truststore) is a
  separate matter from a key you generate. Truststores are reported grouped,
  not once per CA.
- RSA used inside a library you call is not visible. Shorwatch reads your
  sources, configuration and key files, not the code of your dependencies
  (`--classpath` only tells it the types of library methods, never what they
  do). The libraries your build files declare are listed separately, in the
  dependency inventory.
- `SHA256withRSA` is one finding, but `SHA1withRSA` is two: RSA, and
  [SHA-1](sha1.md). Each has its own fix.
- If the same class also uses post-quantum code (an ML-KEM or ML-DSA import,
  an `X25519MLKEM768` string), the finding is reported as `in transition`
  instead of `vulnerable`.

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) and
  [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST IR 8547, the transition timeline](https://csrc.nist.gov/pubs/ir/8547/final)
- Gidney, *How to factor a 2048-bit RSA integer with less than a million noisy
  qubits* (2025), [arXiv:2505.15917](https://arxiv.org/abs/2505.15917)