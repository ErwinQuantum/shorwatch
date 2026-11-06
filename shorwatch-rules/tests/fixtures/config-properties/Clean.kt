package com.example.config

import java.security.MessageDigest

class Clean(private val safe: SafeProperties) {
    fun digest(): MessageDigest = MessageDigest.getInstance(safe.digest)
}
