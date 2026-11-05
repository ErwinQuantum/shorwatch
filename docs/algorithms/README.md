# Why Shorwatch flags what it flags

Every finding in a report links to one of these pages. The report says *what*
to change; these pages say *why*, for the case where you ran the tool, got a
red line and would like to understand it before touching the code.

You don't need a cryptography background. You do need two ideas, and they fit
on this page.

## Two quantum algorithms, two kinds of damage

**Shor's algorithm** (1994) factors integers and computes discrete logarithms
in polynomial time. That is exactly the hard problem behind RSA, Diffie-Hellman,
DSA, ElGamal and every elliptic-curve scheme (ECDH, ECDSA, EdDSA, X25519). On a
large enough quantum computer these are not weakened, they are *broken*: the
private key can be computed from the public one. Making the keys bigger does
not help, because the attack scales polynomially while the keys would have to
grow impractically.

**Grover's algorithm** (1996) speeds up brute-force search by a square root. A
128-bit key that takes 2^128 guesses classically takes about 2^64 Grover
iterations. That is a loss of margin, not a break, and doubling the key size
restores it (AES-256). Grover is also hard to parallelise, so real attacks are
far more expensive than the raw count suggests, which is why NIST still
accepts AES-128.

That difference is the `category` in every Shorwatch finding:

| Category | What happens | What you do |
|---|---|---|
| `shor` | The algorithm is broken, whatever the key size | Replace it with a post-quantum one. Plan a migration. |
| `grover` | The margin shrinks (or the algorithm was weak already) | Move to a bigger key or a stronger hash. Usually a parameter change. |

## Why now, if the machine doesn't exist yet

Two different deadlines hide behind "quantum is coming".

**Confidentiality has already started.** Someone can record your encrypted
traffic today and decrypt it years later, when the machine exists. This is
called *harvest now, decrypt later*. Anything that has to stay secret for a
decade (health records, state secrets, long-lived credentials, source code)
is exposed if it travels under a classical key exchange (RSA, DH, ECDH) and
someone records it. That is why the TLS findings are among the most urgent.

**Authentication has until the machine exists.** A forged signature only helps
an attacker who can forge it *while it still matters*. A TLS handshake signed
with ECDSA today cannot be forged retroactively. The risk is long-lived trust:
a root certificate, a firmware signing key, a code-signing identity or a JWKS
endpoint whose keys stay valid for years, and signed documents that must stay
verifiable for decades. Those keys need a replacement plan before the machine
arrives, not after.

NIST's transition plan (IR 8547) sets the calendar: quantum-vulnerable public
key algorithms are deprecated after 2030 and disallowed after 2035. Migrating a
large codebase, its certificates and its partners takes years, so the work
starts before the deadline.

## The replacements

| Standard | Name | Replaces |
|---|---|---|
| FIPS 203 | ML-KEM (from CRYSTALS-Kyber) | RSA / DH / ECDH for key establishment and encryption |
| FIPS 204 | ML-DSA (from CRYSTALS-Dilithium) | RSA / DSA / ECDSA / EdDSA signatures |
| FIPS 205 | SLH-DSA (from SPHINCS+) | The same signatures, with a conservative hash-based design |

They are not drop-in swaps. A KEM has a different shape than Diffie-Hellman
(one side encapsulates a secret, the other decapsulates it), and the keys and
signatures are much bigger:

| | Public key | Signature / ciphertext |
|---|---|---|
| X25519 | 32 B | none (the public key is the value exchanged) |
| Ed25519 | 32 B | 64 B |
| ECDSA P-256 | 64 B | about 64 B |
| RSA-2048 | 256 B | 256 B |
| ML-KEM-768 | 1,184 B | 1,088 B |
| ML-DSA-44 | 1,312 B | 2,420 B |
| ML-DSA-65 | 1,952 B | 3,309 B |
| ML-DSA-87 | 2,592 B | 4,627 B |
| SLH-DSA (fast and small variants) | 32 to 64 B | about 8 KB to 50 KB |

Those sizes are why a migration touches protocols, certificates, database
columns, header limits and MTUs, and not only the line Shorwatch points at.

## Hybrid, and the "in transition" status

During the move, the usual answer is a **hybrid**: run the classical algorithm
and the post-quantum one together and combine the results, so the connection
is safe if either one holds. `X25519MLKEM768` in TLS 1.3 is the common example,
and it is already deployed by major browsers and CDNs.

When Shorwatch finds a classical algorithm next to post-quantum code, it
reports it as `in transition` instead of `vulnerable`. "Next to" means a
post-quantum library import (such as `org.bouncycastle.pqc.*`) anywhere in the
same file, or a post-quantum type or string (`ML-KEM`, `X25519MLKEM768`, an
ML-DSA type) in the same class. The classical half is expected there. It is
still listed, because once everyone you talk to supports the new algorithms,
the classical half can go.

## The pages

**Public-key algorithms (`shor`)**

- [RSA](rsa.md)
- [Diffie-Hellman](dh.md)
- [DSA](dsa.md)
- [ElGamal](elgamal.md)
- [Elliptic curves, generic](ec.md), [ECDH and X25519](ecdh.md),
  [ECDSA](ecdsa.md), [EdDSA](eddsa.md)
- [TLS key exchange](tls-key-exchange.md)

**The same algorithms inside JWT and JOSE**

- [RSA in JOSE](jose-rsa.md), [ECDSA in JOSE](jose-ecdsa.md),
  [EdDSA in JOSE](jose-eddsa.md), [ECDH in JWE](jose-ecdh.md)

**Symmetric ciphers and hashes (`grover`)**

- [AES-128](aes-128.md), [AES-128 in JWE](jose-aes-128.md)
- [Triple DES](3des.md)
- [SHA-1](sha1.md)

## What these pages don't claim

They explain why Shorwatch reports something. They do not estimate how many
qubits or how much time breaking a given key would take; that needs published
resource estimates. Statements here come from the NIST standards, IETF RFCs and
the references each page links, and the pages are meant to be corrected when
they are wrong. If you find a mistake, open an issue.