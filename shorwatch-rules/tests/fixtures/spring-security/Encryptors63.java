package com.example.config;

import org.springframework.core.io.Resource;
import org.springframework.security.crypto.encrypt.KeyStoreKeyFactory;
import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

/** The same encryptors after Spring Security 6.3 absorbed spring-security-rsa. */
public class Encryptors63 {
    RsaRawEncryptor encryptor(Resource keystore) {
        var keys = new KeyStoreKeyFactory(keystore, "changeit".toCharArray());
        return new RsaRawEncryptor(keys.getKeyPair("config"));
    }
}
