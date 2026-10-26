package com.example.clean

import java.security.Signature

class Clean {
    fun run() {
        Signature.getInstance("ML-DSA-65")
        Signature.getInstance("SLH-DSA-SHA2-128s")
        Signature.getInstance("SHA256withECDSAfoo")
    }
}
