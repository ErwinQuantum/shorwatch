# Diffie-Hellman

Classic (finite-field) Diffie-Hellman falls to Shor's algorithm, and recorded
handshakes are the target.

## What it is

Two parties each pick a secret, exchange public values computed from it, and
end up with the same shared key without ever sending it. In the finite-field
version the public values are powers modulo a large prime (`g^a mod p`). It
shows up as DH, DHE (the ephemeral form used for forward secrecy), "modp"
groups and `DiffieHellman` in most crypto APIs.

## Why it matters

Recovering the secret `a` from `g^a mod p` is the discrete logarithm problem.
It is hard classically, and Shor's algorithm solves it in polynomial time.
An attacker who recorded the exchange can compute the shared key afterwards
and decrypt the session. Longer primes don't help for the same reason they
don't help RSA.

## How urgent

High, and worth planning now. Shorwatch reports it as high severity because it
is key agreement: the session keys it produces protect confidentiality, and
confidentiality is the part exposed to *harvest now, decrypt later*.

Forward secrecy does not rescue it. Ephemeral keys protect against a later
leak of the server key, not against a machine that can solve the discrete log
of each recorded handshake.

NIST IR 8547 deprecates finite-field Diffie-Hellman after 2030 and disallows it
after 2035, and notes that some applications may need to migrate earlier
because of harvest now, decrypt later.

## What to do

Replace the key agreement with a key-encapsulation mechanism: ML-KEM
(FIPS 203). A KEM works differently (one side encapsulates a secret, the
other decapsulates), so this changes the protocol rather than a parameter.
Shorwatch offers no automatic fix for it.

During the transition, run a hybrid: combine the classical shared secret and
the ML-KEM one so that the result holds if either does. Use an approved
combiner, not a hand-rolled one: NIST SP 800-227 (Section 4.6) covers how to
combine key-establishment schemes. Prefer an established hybrid in your
protocol or library over building your own, such as `X25519MLKEM768` in
TLS 1.3 (see [TLS key exchange](tls-key-exchange.md)).

Don't "fix" this by switching to elliptic-curve Diffie-Hellman (ECDH, X25519).
It rests on a different problem, but Shor's algorithm solves that one too.

## Where Shorwatch finds it

- **JCA:** `KeyAgreement`, `KeyPairGenerator`, `KeyFactory` and
  `AlgorithmParameterGenerator` with `DH` or `DiffieHellman`, and
  `DHParameterSpec` / `DHGenParameterSpec`.
- **BouncyCastle:** the DH agreement classes, key pair generators and
  `DHParametersGenerator`.
- **OpenPGP:** the Diffie-Hellman public key tag.
- **JSch and Apache SSHD:** the `diffie-hellman-group*` key exchanges and
  `BuiltinDHFactories`. The hybrid `mlkem768x25519` and `sntrup761x25519`
  factories are not reported.
- **OpenSAML:** the DH key agreement constants.
- **Key material:** DH public keys and certificates (the finding names the
  algorithm, without a size).

DHE cipher suites in a TLS configuration (`TLS_DHE_RSA_WITH_...`) are reported
as [TLS key exchange](tls-key-exchange.md), not here.

## False positives and limits

- Some SSH configurations list `diffie-hellman-group14-sha256` among the key
  exchanges they offer, which does not mean it is the one that ends up in use:
  the peer may negotiate something else. Shorwatch reports it because it is
  offered.
- The elliptic-curve variant is [ECDH](ecdh.md), a separate finding. A list
  such as `diffie-hellman-group14-sha256,curve25519-sha256` gets one finding
  for each.
- Shorwatch reports the use of Diffie-Hellman, not the size of the group, so a
  1024-bit group and a 4096-bit one are the same finding.
- A DH key that BouncyCastle's lightweight API only describes (`DHParameters`,
  `DHStandardGroups`) is not reported until something generates a key or
  agrees on a secret with it.

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST SP 800-227, recommendations for key-encapsulation mechanisms](https://csrc.nist.gov/pubs/sp/800/227/final)
- [NIST IR 8547, Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/final)