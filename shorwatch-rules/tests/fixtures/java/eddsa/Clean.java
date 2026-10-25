package com.example.clean;

import java.security.Signature;

public class Clean {
    void run() throws Exception {
        Signature.getInstance("ML-DSA-87");
        Signature.getInstance("Ed25519-preview");
    }
}
