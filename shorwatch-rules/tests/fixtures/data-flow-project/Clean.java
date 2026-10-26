package com.example.billing;

import java.security.MessageDigest;

public class Clean {
    /** The same helper, called with SHA-256: this call's argument, not another's. */
    byte[] checksum(byte[] data) throws Exception {
        return MessageDigest.getInstance(Algorithms.identity("SHA-256")).digest(data);
    }
}
