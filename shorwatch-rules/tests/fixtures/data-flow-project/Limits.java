package com.example.billing;

import java.security.MessageDigest;

/**
 * Not followed: which overload a call picks depends on the argument types,
 * so neither is. No findings here, although SHA-1 reaches getInstance.
 */
public class Limits {
    void digest(String algorithm) throws Exception {
        MessageDigest.getInstance(algorithm);
    }

    void digest(StringBuilder algorithm) throws Exception {
        MessageDigest.getInstance(algorithm.toString());
    }

    void legacy() throws Exception {
        digest("SHA-1");
    }
}
