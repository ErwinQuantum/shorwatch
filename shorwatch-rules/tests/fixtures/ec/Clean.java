package com.example.clean;

import java.security.KeyPairGenerator;

public class Clean {
    void run() throws Exception {
        KeyPairGenerator.getInstance("ML-DSA");
        // Not "EC": only the exact name is ambiguous.
        KeyPairGenerator.getInstance("ECX");
        // Other types' nested builders are not Nimbus' `ECKey.Builder`.
        new Settings.Builder().build();
        new Builder();
    }

    static class Builder {}
}
