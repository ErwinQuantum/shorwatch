package com.example.clean;

import java.security.Signature;

public class Clean {
    void run() throws Exception {
        Signature.getInstance("ML-DSA-44");
        // ML-DSA ends in "DSA" but is not DSA.
        Signature.getInstance("SHA512withML-DSA");
    }
}
