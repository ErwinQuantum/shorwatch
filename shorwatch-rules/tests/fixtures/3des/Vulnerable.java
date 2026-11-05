package com.example.legacy;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.engines.DESedeEngine;

public class Vulnerable {
    private static final String ALGORITHM = "DESede";

    Cipher cipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    SecretKey generate() throws Exception {
        return KeyGenerator.getInstance(ALGORITHM).generateKey();
    }

    SecretKey wrap(byte[] raw) {
        return new SecretKeySpec(raw, "TripleDES");
    }

    Object lightweight() {
        return new DESedeEngine();
    }

    /** Key wrapping, and password-based encryption over Triple DES. */
    void variants() throws Exception {
        Cipher.getInstance("DESedeWrap");
        Cipher.getInstance("PBEWithMD5AndTripleDES");
        SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
    }

    /** OpenSSL names write Triple DES as DES-CBC3. */
    String[] openSslSuites() {
        return new String[] {"DES-CBC3-SHA", "HIGH:!3DES"};
    }
}
