package com.example.keys;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public class Clean {
    enum Safe {
        BULK("AES/GCM/NoPadding"),
        DIGEST("SHA-256");

        private final String jceName;

        Safe(String jceName) {
            this.jceName = jceName;
        }

        String getJceName() {
            return jceName;
        }
    }

    // Every constant of the enum is safe.
    Cipher cipher(Safe safe) throws Exception {
        return Cipher.getInstance(safe.getJceName());
    }

    // A specific constant is not widened to the others: SESSION is AES.
    Cipher session() throws Exception {
        return Cipher.getInstance(KeyKind.SESSION.getJceName());
    }

    // `name()` of an enum with safe constants only.
    MessageDigest digest(Hashes hashes) throws Exception {
        return MessageDigest.getInstance(hashes.name());
    }

    enum Hashes {
        SHA3_256,
        SHA_512
    }
}
