## 🛡️ Shorwatch: 10 quantum-vulnerable findings

| | Count |
|---|---:|
| Vulnerable | 9 |
| In transition (hybrid) | 1 |
| Auto-fixable | 1 |
| Severity high | 7 |
| Severity medium | 2 |
| Severity low | 1 |
| Files with findings / scanned | 6 / 6 |

### Findings

| Severity | Algorithm | Location | Status | Rule |
|---|---|---|---|---|
| high | RSA (JOSE/JWT) | `examples/spring-service/src/main/java/com/example/payments/auth/AuthorizationServerConfig.java:23` | vulnerable | `jvm.nimbus.jose-rsa` |
| high | RSA | `examples/spring-service/src/main/java/com/example/payments/auth/AuthorizationServerConfig.java:32` | vulnerable | `jvm.jca.rsa` |
| high | ECDSA (JOSE/JWT) | `examples/spring-service/src/main/java/com/example/payments/auth/TokenSigner.java:14` | vulnerable | `jvm.nimbus.jose-ecdsa` |
| medium | SHA-1 | `examples/spring-service/src/main/java/com/example/payments/crypto/LegacyCrypto.java:13` | vulnerable | `jvm.jca.sha1` |
| medium | 3DES | `examples/spring-service/src/main/java/com/example/payments/crypto/LegacyCrypto.java:17` | vulnerable | `jvm.jca.3des` |
| low | AES-128 | `examples/spring-service/src/main/java/com/example/payments/crypto/LegacyCrypto.java:22` | vulnerable | `jvm.jca.aes-128` |
| high | ECDH | `examples/spring-service/src/main/java/com/example/payments/tls/HybridKeyExchange.java:9` | in transition | `jvm.jca.ecdh` |
| high | ECDSA (JOSE/JWT) | `examples/spring-service/src/main/resources/application-prod.yml:4` | vulnerable | `config.app.jose-ecdsa` |
| high | RSA (JOSE/JWT) | `examples/spring-service/src/main/resources/application.yml:8` | vulnerable | `config.spring-boot.jose-rsa` |
| high | TLS key exchange | `examples/spring-service/src/main/resources/application.yml:14` | vulnerable | `config.spring-boot.tls-key-exchange` |
