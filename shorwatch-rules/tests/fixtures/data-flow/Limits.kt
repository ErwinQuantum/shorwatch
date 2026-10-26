package com.example.payments

import java.security.MessageDigest

/**
 * What data flow deliberately does not follow, so this file has no findings
 * although it uses SHA-1: an overloaded method, whose target needs the
 * argument types, and a cycle between variables.
 */
class Limits {
    fun hash(algorithm: String) {
        MessageDigest.getInstance(algorithm)
    }

    fun hash(algorithm: StringBuilder) {
        MessageDigest.getInstance(algorithm.toString())
    }

    fun legacy() {
        hash("SHA-1")
    }

    fun cycle(flip: Boolean) {
        var a = "SHA-256"
        var b = a
        a = b
        MessageDigest.getInstance(a)
    }
}
