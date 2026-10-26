package com.example.billing;

import java.security.MessageDigest;

/** The algorithm arrives through the constructor, from another file. */
public class Checksums {
    private final String algorithm;

    public Checksums(String algorithm) {
        this.algorithm = algorithm;
    }

    byte[] of(byte[] data) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(data);
    }
}
