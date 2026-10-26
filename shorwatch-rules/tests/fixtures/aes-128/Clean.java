package com.example.clean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;

public class Clean {
    void run(byte[] iv) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        Cipher.getInstance("AES_256/GCM/NoPadding");
        // 128 here is the GCM tag length in bits, not a key size.
        new GCMParameterSpec(128, iv);
        // An HMAC key generator: 128 bits is a MAC key size, not AES.
        KeyGenerator hmac = KeyGenerator.getInstance("HmacSHA256");
        hmac.init(128);
        // Not a KeyGenerator.
        java.util.zip.Deflater deflater = new java.util.zip.Deflater();
        deflater.setLevel(128);
    }
}
