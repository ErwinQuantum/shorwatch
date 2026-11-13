# ECDH, X25519 and X448

Elliptic-curve key agreement is broken by Shor's algorithm. X25519 is a good
curve and a bad long-term bet.

## What it is
ECDH is Diffie-Hellman on an elliptic curve: two parties derive a shared
secret from each other's public keys. X25519 and X448 are the same idea on
Montgomery curves, designed to be fast and hard to implement wrongly. They are
what modern TLS 1.3, SSH, Signal, WireGuard and most new protocols use. ECIES
(encrypting to a recipient's EC public key), ECMQV and the HPKE DH-KEMs are
close relatives and count here too.

## Why it matters
Shor's algorithm solves the elliptic-curve discrete logarithm problem, which is
the only thing protecting the shared secret. A quantum computer that can run it
at scale recovers the private key from a public key, and with it every secret
that was derived from it.

X25519 is a well-designed curve: it is fast, it avoids many implementation
mistakes, and classically it is very strong. None of that helps here. Against
a quantum attacker it is exactly as exposed as any other elliptic curve.

## How urgent
Urgent, and more than for signatures. This is key agreement, so an attacker
does not need a quantum computer today. They can record encrypted traffic now
and decrypt it years later (harvest now, decrypt later). Forward secrecy
does not change this: it limits the damage of a stolen long-term key, but a
quantum attacker breaks each recorded exchange on its own.

Severity: **High**. Shorwatch never offers an automatic fix for this class.
The replacement is a design decision, not a one-line edit.

## What to do
Move key establishment to ML-KEM (FIPS 203). The practical route is a hybrid
that combines X25519 with ML-KEM, `X25519MLKEM768` in TLS 1.3, so a break in
either half alone does not expose the key. Browsers and CDNs already negotiate
it (Chrome and Firefox by default), and it is standardized for TLS 1.3 in RFC
10024.

For TLS, whether this is a configuration change depends on your stack: you need
a TLS library or JDK that supports the hybrid group. Check your runtime's
support before assuming an upgrade is enough.

For application-level protocols (your own handshake, ECIES, message
encryption) it is a real redesign. ML-KEM is a KEM, not Diffie-Hellman: you
encapsulate a key to the recipient and use it with an AEAD. When combining it
with a classical secret, use one of the key combiners NIST SP 800-227
approves (§4.6.2: a key-derivation method of SP 800-56C or a key-combination
method of SP 800-133). If you combine by concatenation, pass the result through
a KDF and encode the inputs with their lengths, as NIST asks; the raw
concatenation is not a key.

## Where Shorwatch finds it

- **JCA:** `KeyAgreement` with `ECDH`, `ECDHC`, `ECCDH`, `ECMQV` (also with a
  KDF suffix such as `ECDHwithSHA256KDF`), `XDH`, `X25519` or `X448`;
  `KeyPairGenerator` and `KeyFactory` with the same names; `Cipher` with
  `ECIES`; and `XECPublicKeySpec` / `XECPrivateKeySpec`.
- **BouncyCastle:** the `ECDH`, `ECDHC`, `ECMQV` and unified-model agreement
  classes, `X25519Agreement` / `X448Agreement` and their key pair generators.
- **BouncyCastle for .NET:** the `ECDH`, `ECDHC` and `ECMqv` agreement classes
  (with and without a key derivation function), `X25519Agreement` /
  `X448Agreement` and their key pair generators, and an ECDH name given to
  `AgreementUtilities.GetBasicAgreement`.
- **Tink:** the ECIES and HPKE templates with a classical DH-KEM.
- **OpenPGP:** the ECDH, X25519 and X448 public key tags.
- **.NET:** `ECDiffieHellman.Create`, `ECDiffieHellmanCng` and
  `ECDiffieHellmanOpenSsl`.
- **JSch and Apache SSHD:** the `ecdh-sha2-nistp*` and `curve25519`/`curve448`
  key exchanges.
- **OpenSAML:** the ECDH key agreement constants.
- **AWS KMS:** `KeyAgreementAlgorithmSpec.ECDH`.
- **Key material:** X25519 and X448 keys in PEM and DER files. Other
  elliptic-curve keys are reported as [generic EC](ec.md).

The JWT flavour (`ECDH-ES`) is on [its own page](jose-ecdh.md); TLS is covered
in [TLS key exchange](tls-key-exchange.md).

## False positives and limits
- Shorwatch reports the algorithm it sees. If it also sees post-quantum code
  nearby, it marks the finding `in transition` instead of `vulnerable`. "Nearby"
  means: a post-quantum import (for example `org.bouncycastle.pqc.*`) anywhere
  in the same file, or a post-quantum type or literal (`ML-KEM`, `Kyber`,
  `X25519MLKEM768`) in the same class.
- `in transition` is not a pass. Shorwatch cannot check that the hybrid is
  actually wired in, only that post-quantum code is present next to the
  classical one.
- Shorwatch looks at source and configuration. A TLS group negotiated by the
  JDK or a load balancer at runtime is not visible to it.
- Classes that only describe an X25519 key or a curve (`X25519PublicKeyParameters`,
  `NamedParameterSpec.X25519`) are not reported by themselves. The generator
  or agreement that uses them is.
- BouncyCastle's `IESEngine` (ECIES in the lightweight API) is reported through
  the agreement it is given, such as `ECDHBasicAgreement`, not on its own. The
  same goes for BouncyCastle's own `HPKE` class: its classical KEM constants
  are not matched yet.

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST SP 800-227, KEM recommendations](https://csrc.nist.gov/pubs/sp/800/227/final)
- [RFC 10024, Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024)
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)
