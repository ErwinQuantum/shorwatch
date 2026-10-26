package com.example.config

import org.springframework.core.io.Resource
import org.springframework.security.crypto.encrypt.KeyStoreKeyFactory
import org.springframework.security.crypto.encrypt.RsaRawEncryptor

/** The same encryptors after Spring Security 6.3 absorbed spring-security-rsa. */
class Encryptors63 {
    fun encryptor(keystore: Resource): RsaRawEncryptor {
        val keys = KeyStoreKeyFactory(keystore, "changeit".toCharArray())
        return RsaRawEncryptor(keys.getKeyPair("config"))
    }
}
