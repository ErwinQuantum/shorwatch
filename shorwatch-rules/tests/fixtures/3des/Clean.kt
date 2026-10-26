package com.example.clean

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Clean {
    fun run(raw: ByteArray) {
        Cipher.getInstance("AES/GCM/NoPadding")
        SecretKeySpec(raw, "AES")
        // Unrelated algorithm whose name starts the same way.
        Cipher.getInstance("DESX/CBC/NoPadding")
    }
}
