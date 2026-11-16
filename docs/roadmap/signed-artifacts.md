# Signed artifacts

**Status: planned, not implemented.**

## The problem

Shorwatch reads the keys and certificates a repository holds, but not the
signatures **inside** the files it ships. A signed JAR carries its signer's
certificate and the algorithm of the signature; an Android package carries
a signing certificate. Both are quantum-vulnerable public-key cryptography
sitting in a file that is not a key file.

## What it would do

- **Signed JARs in the repository:** read the signature block under
  `META-INF/` (a PKCS#7 structure) and report the signer's key and signature
  algorithm like any other certificate.
- **Signing in build files:** the signature algorithm a build asks for
  (jarsigner options, Android signing configurations, Gradle signing blocks).
- **Android packages**, later: their signing block has its own format.

## How it would fit

- The key-material reader already parses certificates by hand, with bounded
  input. A PKCS#7 reader is the same kind of code over a container format.
- The archive reader already exists for compiled dependencies.
- The build-file frontends would emit the signing settings as facts, and rules
  would match them.

## Left out

- Container image and package-manager signatures, which are not in the
  repository.
- Verifying signatures. Shorwatch inventories the algorithm, not trust.

## Undecided

- Whether a signature algorithm in a JAR is a finding in its own right or only
  a property of the certificate that is already reported.
