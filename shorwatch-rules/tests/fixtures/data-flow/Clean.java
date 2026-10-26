package com.example.payments;

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class Clean {
    byte[] digest(byte[] data, String algorithm) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(data);
    }

    byte[] fingerprint(byte[] data) throws Exception {
        return digest(data, "SHA-256");
    }

    Cipher cipher(boolean fast) throws Exception {
        String transformation = fast ? "ChaCha20-Poly1305" : "AES/GCM/NoPadding";
        return Cipher.getInstance(transformation);
    }
}
