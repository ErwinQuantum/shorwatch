package com.example.payments;

import java.security.MessageDigest;

/**
 * What data flow deliberately does not follow, so this file has no findings
 * although it uses SHA-1: an overloaded method, whose target needs the
 * argument types, and a cycle between variables.
 */
public class Limits {
    void hash(String algorithm) throws Exception {
        MessageDigest.getInstance(algorithm);
    }

    void hash(StringBuilder algorithm) throws Exception {
        MessageDigest.getInstance(algorithm.toString());
    }

    void legacy() throws Exception {
        hash("SHA-1");
    }

    void cycle(boolean flip) throws Exception {
        String a = "SHA-256";
        String b = a;
        a = b;
        MessageDigest.getInstance(a);
    }
}
