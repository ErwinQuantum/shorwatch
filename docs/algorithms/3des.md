# Triple DES (3DES)

3DES is retired for reasons that have nothing to do with quantum computers,
and Grover's algorithm leaves it with very little margin on top.

## What it is

Triple DES (also TDEA, `DESede`) applies the old DES cipher three times with
two or three keys. It was the stopgap that let banks and payment systems keep
using DES hardware once DES itself could be broken, from the late 1990s on, and
it is still found in old payment code, legacy TLS configurations and some XML
encryption.

## Why it matters

Three problems, from most to least immediate:

1. **The 64-bit block.** Encrypting a lot of data under one key makes block
   collisions likely: after about 32 GB (2^32 blocks of 8 bytes) they are
   expected. The Sweet32 attack (2016) turned that into practice, recovering
   secrets such as HTTP cookies from long-lived TLS and OpenVPN connections. It
   needed far more traffic than 32 GB and a secret that repeats, but it showed
   the limit is real. NIST's own limit is much tighter: SP 800-67 Rev. 2
   allowed three-key TDEA to protect no more than 2^20 blocks (8 MiB) under one
   key.
2. **The effective strength.** Because of meet-in-the-middle attacks, three-key
   3DES gives 112 bits of security classically, not the 168 its keys suggest.
3. **Grover.** Quantum attacks shrink whatever margin is left. A plain Grover
   search over the full 168-bit key already brings it down to about 84 bits, and
   attacks that exploit the meet-in-the-middle structure may bring it lower. In
   practice Grover costs more than these numbers suggest, because it does not
   parallelize well, but starting from 112 bits there isn't much margin to spend.

NIST has retired it: SP 800-131A Rev. 2 disallows three-key TDEA for encryption
after 2023, while decrypting data that is already encrypted remains allowed for
legacy use. SP 800-67 Rev. 2, which specified the algorithm, was withdrawn on
1 January 2024.

## How urgent

Higher than AES-128 and independent of quantum. If you use 3DES to encrypt new
data, that is a bug today.

## What to do

Use AES-256, preferably in an authenticated mode such as GCM.

Shorwatch offers no automatic fix, and this one is not simple: AES-256 has a
different key size (32 bytes, not 3DES's 24), IV length (16 bytes, not 8) and
block size (128 bits, not 64). And data already encrypted with 3DES has to be
decrypted and re-encrypted: changing the code does not change what is already
stored.

If you are only *reading* legacy data, plan a one-time migration and stop
writing with 3DES in the meantime.

## Where Shorwatch finds it

- **JCA:** `DESede`, `TripleDES` and `3DES` as `Cipher`, `KeyGenerator` and
  `SecretKeyFactory` names (`DESede/CBC/PKCS5Padding`), the key-wrapping
  `DESedeWrap`, the password-based `PBEWithMD5AndTripleDES` and
  `PBEWithSHA1AndDESede`, `DESedeKeySpec`, and a `SecretKeySpec` for `DESede`.
- **BouncyCastle:** `DESedeEngine` and `DESedeWrapEngine`.
- **OpenPGP, XML Encryption (Santuario) and OpenSAML:** their Triple DES tags
  and constants.
- **TLS:** cipher suites containing `3DES_EDE_CBC` or, in OpenSSL form,
  `DES-CBC3-SHA` (also with a key-exchange prefix), in code, in OkHttp's
  `ConnectionSpec` and in Spring Boot cipher lists.
- **Jasypt:** `jasypt.encryptor.algorithm` set to a password-based name over
  Triple DES, the usual place to find it in a Spring Boot service.

## False positives and limits

- Single DES (`DES/CBC/PKCS5Padding`, `PBEWithMD5AndDES`) is a different and
  weaker algorithm. Shorwatch has no rule for it, so it is not reported.
  The same goes for RC4 and MD5.
- A bare `3DES` in an OpenSSL cipher string is not reported, because it is
  mostly written as an exclusion (`HIGH:!3DES`).
- The size of the data protected under one key is not visible, so Shorwatch
  cannot tell a use that stays under NIST's block limit from one that does not.

## References

- [NIST SP 800-131A Rev. 2, transitioning the use of cryptographic algorithms and key lengths](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [NIST SP 800-67 Rev. 2 (withdrawn), recommendation for the Triple Data Encryption Algorithm](https://csrc.nist.gov/pubs/sp/800/67/r2/final)
- [Sweet32: birthday attacks on 64-bit block ciphers in TLS and OpenVPN](https://sweet32.info/)