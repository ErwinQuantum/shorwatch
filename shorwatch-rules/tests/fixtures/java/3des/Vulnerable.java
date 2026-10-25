package com.example.legacy;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
}
