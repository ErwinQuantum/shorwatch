package com.example.config;

import java.security.MessageDigest;

public class Clean {
    private final SafeProperties safe;

    Clean(SafeProperties safe) {
        this.safe = safe;
    }

    MessageDigest digest() throws Exception {
        return MessageDigest.getInstance(safe.getDigest());
    }
}
