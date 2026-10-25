package com.example.clean;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Clean {
    void run(byte[] raw) throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
        new SecretKeySpec(raw, "AES");
        // Unrelated algorithm whose name starts the same way.
        Cipher.getInstance("DESX/CBC/NoPadding");
    }
}
