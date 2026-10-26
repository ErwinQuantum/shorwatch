package com.example.payments.crypto;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Kept for the v1 card vault. */
public final class LegacyCrypto {
    private static final String VAULT_CIPHER = "DESede/CBC/PKCS5Padding";

    static byte[] fingerprint(byte[] card) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(card);
    }

    static Cipher vaultCipher() throws Exception {
        return Cipher.getInstance(VAULT_CIPHER);
    }

    static SecretKey sessionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }
}
