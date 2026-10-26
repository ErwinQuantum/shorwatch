package com.example.clean

import java.security.KeyPairGenerator
import java.security.Signature
import javax.crypto.Cipher

class Clean {
    fun run(configured: String) {
        KeyPairGenerator.getInstance("ML-KEM-768")
        Signature.getInstance("ML-DSA-65")
        Cipher.getInstance("AES/GCM/NoPadding")
        // Not a JCA receiver, so not a finding.
        com.example.Registry().getInstance("RSA")
        // Value unknown statically: left to future data-flow analysis.
        Cipher.getInstance(configured)
        // A template is only known at run time.
        Cipher.getInstance("$configured/ECB/PKCS1Padding")
        val log = "migrated away from RSA"
    }
}
