# TLS key exchange

TLS connections that use RSA, DHE or ECDHE for key exchange can be recorded
today and decrypted later. This is among the most time-sensitive findings
Shorwatch produces.

## What it is

When a TLS connection starts, client and server agree on a session key. The
key exchange is the step that does it: static RSA (the client encrypts a
secret to the server's RSA key), DHE (ephemeral Diffie-Hellman) or ECDHE
(ephemeral elliptic-curve Diffie-Hellman, today's default). Shorwatch looks at
the TLS 1.2 cipher suites a program or configuration enables, such as
`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, and at classical named groups set in
the `jdk.tls.namedGroups` property.

## Why it matters

All three exchanges rest on problems Shor's algorithm solves. Someone who
records the encrypted traffic, and the handshake with it, can recover the
session key once a quantum computer able to do it exists and read everything
in the session. Nothing needs to be attacked now; copying packets is enough.

Static RSA is worse: it has no forward secrecy even classically. One leaked
server key decrypts every past session recorded with it. TLS 1.3 removed that
mode entirely.

## How urgent

Among the most urgent, because it is a case where waiting makes the damage
bigger. Data in transit today with a secrecy requirement of ten years or more
(health, finance, government, intellectual property) is already exposed to
this model.

Note what is *not* urgent here for recorded traffic: the certificate.
Authentication happens in real time, so a handshake signed with ECDSA today
can't be forged retroactively. The certificate's long-lived keys still need
their own migration (see [ECDSA](ecdsa.md)), but hybrid key exchange fixes the
confidentiality problem without waiting for post-quantum certificates.

Severity: **High**. Shorwatch never offers an automatic fix for this class.

## What to do

- Prefer TLS 1.3.
- Enable a hybrid post-quantum key exchange group, `X25519MLKEM768`, wherever
  your TLS stack and peers support it, and keep a classical group as a
  fallback while others catch up. Recent browsers and CDNs already offer it.
  The hybrid is standardized for TLS 1.3 in RFC 10024, on top of the general
  framework in RFC 9954.
- In Java, support depends on the JDK or provider you run. Check your
  runtime before assuming a configuration change is enough.
- Remove static RSA suites (`TLS_RSA_WITH_*`) now, regardless of quantum.
- Check the pieces in between: load balancers, proxies, service meshes and
  JVM versions decide what is actually negotiated, not only your application
  code.

## Where Shorwatch finds it

- **Code:** TLS 1.2 suite names written as strings, wherever they appear:
  JSSE `setEnabledCipherSuites`, Netty, Jetty, Tomcat connectors and similar.
  Both IANA names (`TLS_ECDHE_RSA_…`) and OpenSSL names (`ECDHE-RSA-…`) match.
  Static RSA has no key-exchange prefix in OpenSSL names, so the common ones
  are listed by name (`AES128-SHA`, `AES256-SHA`, `AES128-GCM-SHA256`,
  `AES256-GCM-SHA384`, `DES-CBC3-SHA`, `RC4-SHA`, the Camellia and SEED
  variants). Static DH and ECDH suites (`TLS_DH_…`, `TLS_ECDH_…`) and the
  PSK variants that still use RSA or ECDHE are matched as well.
  A call that sets `jdk.tls.namedGroups` to a classical group (`x25519`,
  `x448`, `secp256r1`, `ffdhe…`) is reported too, and so is a classical group
  name passed to `SSLParameters.setNamedGroups`.
- **OkHttp:** the `CipherSuite` constants in a `ConnectionSpec`.
- **Configuration:** Spring Boot's `server.ssl.ciphers`, the management
  server's, SSL bundles (`spring.ssl.bundle.*.options.ciphers`), any other
  `*.ssl.ciphers` or `*.ssl.cipher-suites` key (Quarkus and Micronaut use
  these) and Kafka's `ssl.cipher.suites`, including when it is passed through
  Spring Boot's `spring.kafka.properties`.

## False positives and limits

- Shorwatch sees the TLS 1.2 suite names. TLS 1.3 suites such as
  `TLS_AES_256_GCM_SHA384` don't name a key exchange, so a configuration that
  is TLS 1.3 only is not reported on that basis, even though it still uses
  ECDHE unless a hybrid group is negotiated.
- A suite in an *allow* list is not necessarily the one negotiated. If both
  sides prefer TLS 1.3, the TLS 1.2 list never gets used. Shorwatch reports
  what is enabled.
- A suite passed to an exclusion call (`setExcludeCipherSuites` and similar)
  is not reported as enabled.
- Because Shorwatch matches suite names as text, a name in a log message or
  a test can produce a finding.
- The `jdk.tls.namedGroups` check reads `System.setProperty` calls whose key
  is `jdk.tls.namedGroups` (or the same name with a one-word prefix between
  `tls.` and `namedGroups`); the same group under another key is not reported.
- `SSLParameters.setNamedGroups` is read only when the group names are written
  in the call (a literal array or arguments), not when the array comes from a
  variable.
- Pure pre-shared-key suites (`TLS_PSK_WITH_…`) have no public-key exchange
  and are not reported. SRP suites (`TLS_SRP_…`) are not matched either.
- Only what is written in code and in Spring-style configuration is read. A
  Tomcat `server.xml` connector, an `nginx.conf` or a `sshd_config` is not.
- OpenSSL static RSA names are matched by a list of the common ones. A rare
  name outside it is missed.
- Hybrid support depends on the runtime, not only on the code. If your code
  mentions `X25519MLKEM768`, Shorwatch treats nearby classical findings as
  `in transition`. It can't tell that the JVM actually provides the group.

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [RFC 9954, Hybrid Key Exchange in TLS 1.3](https://www.rfc-editor.org/rfc/rfc9954)
- [RFC 10024, Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024)
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)