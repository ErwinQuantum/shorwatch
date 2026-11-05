package com.example.legacy;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Vulnerable {
    private static final int KEY_BITS = 128;

    SecretKey literal() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }

    Cipher pinnedTransformation() throws Exception {
        return Cipher.getInstance("AES_128/GCM/NoPadding");
    }

    /** Found, but no fix: the edit belongs on the constant, not here. */
    SecretKey viaConstant() throws Exception {
        var generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_BITS);
        return generator.generateKey();
    }

    /** Found, but no fix: the literal is not written as plain `128`. */
    SecretKey hex(java.security.SecureRandom random) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(0x80, random);
        return generator.generateKey();
    }

    /** OpenSSL names write the key size without an underscore. */
    String[] openSslSuites() {
        return new String[] {"ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA"};
    }

    /** Created elsewhere: the algorithm is unknown, so it is still reported. */
    SecretKey injected(KeyGenerator generator) {
        generator.init(128);
        return generator.generateKey();
    }
}
