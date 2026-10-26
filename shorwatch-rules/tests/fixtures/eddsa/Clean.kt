package com.example.clean

import java.security.Signature

class Clean {
    fun run() {
        Signature.getInstance("ML-DSA-87")
        Signature.getInstance("Ed25519-preview")
    }
}
