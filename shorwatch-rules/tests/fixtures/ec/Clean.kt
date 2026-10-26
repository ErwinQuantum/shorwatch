package com.example.clean

import java.security.KeyPairGenerator

class Clean {
    fun run() {
        KeyPairGenerator.getInstance("ML-DSA")
        // Not "EC": only the exact name is ambiguous.
        KeyPairGenerator.getInstance("ECX")
    }
}
