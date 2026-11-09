## 🛡️ Shorwatch: 17 quantum-vulnerable findings

| | Count |
|---|---:|
| Vulnerable | 16 |
| In transition (hybrid) | 1 |
| With a suggested fix | 1 |
| Severity high | 13 |
| Severity medium | 3 |
| Severity low | 1 |
| Files with findings / scanned | 9 / 10 |

Analyzed: 5 Java · 2 YAML · 1 Kotlin · 1 Maven · 1 key material.

### Findings

| Severity | Algorithm | Location | Status | Rule |
|---|---|---|---|---|
| high | RSA \(JOSE/JWT\) | `examples/spring-service/src/main/java/com/example/payments/auth/AuthorizationServerConfig.java:23` | vulnerable | `jvm.nimbus.jose-rsa` |
| high | RSA | `examples/spring-service/src/main/java/com/example/payments/auth/AuthorizationServerConfig.java:32` | vulnerable | `jvm.jca.rsa` |
| high | ECDSA \(JOSE/JWT\) | `examples/spring-service/src/main/java/com/example/payments/auth/TokenSigner.java:14` | vulnerable | `jvm.nimbus.jose-ecdsa` |
| medium | SHA-1 | `examples/spring-service/src/main/java/com/example/payments/crypto/LegacyCrypto.java:13` | vulnerable | `jvm.jca.sha1` |
| medium | 3DES | `examples/spring-service/src/main/java/com/example/payments/crypto/LegacyCrypto.java:17` | vulnerable | `jvm.jca.3des` |
| low | AES-128 | `examples/spring-service/src/main/java/com/example/payments/crypto/LegacyCrypto.java:22` | vulnerable | `jvm.jca.aes-128` |
| high | ECDSA | `examples/spring-service/src/main/java/com/example/payments/partners/StatementSigner.java:9` (value from line 19) | vulnerable | `jvm.jca.ecdsa` |
| high | RSA | `examples/spring-service/src/main/java/com/example/payments/partners/StatementSigner.java:9` (value from line 18) | vulnerable | `jvm.jca.rsa` |
| medium | SHA-1 | `examples/spring-service/src/main/java/com/example/payments/partners/StatementSigner.java:9` (value from line 18) | vulnerable | `jvm.jca.sha1` |
| high | ECDH | `examples/spring-service/src/main/java/com/example/payments/tls/HybridKeyExchange.java:9` | in transition | `jvm.jca.ecdh` |
| high | ECDSA \(JOSE/JWT\) | `examples/spring-service/src/main/kotlin/com/example/payments/partners/PartnerKeys.kt:16` | vulnerable | `jvm.nimbus.jose-ecdsa` |
| high | ECC | `examples/spring-service/src/main/kotlin/com/example/payments/partners/PartnerKeys.kt:19` | vulnerable | `jvm.jca.ec` |
| high | ECC | `examples/spring-service/src/main/kotlin/com/example/payments/partners/PartnerKeys.kt:20` | vulnerable | `jvm.jca.ec` |
| high | ECDSA \(JOSE/JWT\) | `examples/spring-service/src/main/resources/application-prod.yml:4` | vulnerable | `config.app.jose-ecdsa` |
| high | RSA \(JOSE/JWT\) | `examples/spring-service/src/main/resources/application.yml:8` | vulnerable | `config.spring-boot.jose-rsa` |
| high | TLS key exchange | `examples/spring-service/src/main/resources/application.yml:14` | vulnerable | `config.spring-boot.tls-key-exchange` |
| high | RSA | `examples/spring-service/src/main/resources/certs/partner-signing.pem:1` (certificate "CN=statements.partner.example, O=Example Partner": RSA 3072-bit, signed with SHA256withRSA, valid until 2031-10-26) | vulnerable | `keys.material.rsa` |

### Cryptographic libraries

| Library | Version | Post-quantum | Declared in |
|---|---|---|---|
| Spring Security \(OAuth 2.0 and JOSE\) | not set |  | `examples/spring-service/pom.xml:25` |
| Spring Security \(OAuth 2.0 and JOSE\) | not set |  | `examples/spring-service/pom.xml:29` |
| BouncyCastle | 1.70 | not before 1.79 | `examples/spring-service/pom.xml:33` |
| Nimbus JOSE + JWT | 9.37.3 |  | `examples/spring-service/pom.xml:38` |
| JSch | 0.1.55 |  | `examples/spring-service/pom.xml:43` |
