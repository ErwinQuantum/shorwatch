package com.example.clean;

import java.security.Signature;

public class Clean {
    void run() throws Exception {
        Signature.getInstance("ML-DSA-65");
        Signature.getInstance("SLH-DSA-SHA2-128s");
        Signature.getInstance("SHA256withECDSAfoo");
    }
}
