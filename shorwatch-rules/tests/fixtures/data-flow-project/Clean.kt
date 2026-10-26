package com.example.billing.kt

import java.security.MessageDigest

class Clean {
    /** The same helper, called with SHA-256: this call's argument, not another's. */
    fun checksum(data: ByteArray): ByteArray =
        MessageDigest.getInstance(Algorithms.identity("SHA-256")).digest(data)
}
