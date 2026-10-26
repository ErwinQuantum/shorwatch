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
        // Not a KeyGenerator.
        java.util.zip.Deflater deflater = new java.util.zip.Deflater();
        deflater.setLevel(128);
    }
}
