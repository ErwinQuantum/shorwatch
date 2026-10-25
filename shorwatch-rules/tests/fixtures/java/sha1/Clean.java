package com.example.clean;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

public class Clean {
    void run() throws Exception {
        MessageDigest.getInstance("SHA-256");
        MessageDigest.getInstance("SHA3-256");
        MessageDigest.getInstance("SHA-512/256");
        // Not collision-dependent: intentionally not reported.
        Mac.getInstance("HmacSHA1");
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
