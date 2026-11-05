package com.example.clean;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;

public class Clean {
    void run() throws Exception {
        MessageDigest.getInstance("SHA-256");
        MessageDigest.getInstance("SHA3-256");
        MessageDigest.getInstance("SHA-512/256");
        // Not collision-dependent: intentionally not reported.
        Mac.getInstance("HmacSHA1");
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        Cipher.getInstance("AES/GCM/NoPadding");
        // The same APIs with a SHA-2 algorithm, and an HMAC URI.
        new MessageDigestPasswordEncoder("SHA-256");
        Object algorithm = MessageDigestAlgorithms.SHA_256;
        String hmac = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    }
}
