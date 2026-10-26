package com.example.clean

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class Clean {
    fun run(iv: ByteArray) {
        KeyGenerator.getInstance("AES").apply { init(256) }
        Cipher.getInstance("AES_256/GCM/NoPadding")
        // 128 here is the GCM tag length in bits, not a key size.
        GCMParameterSpec(128, iv)
        // Not a KeyGenerator.
        val deflater = java.util.zip.Deflater()
        deflater.setLevel(128)
    }
}
