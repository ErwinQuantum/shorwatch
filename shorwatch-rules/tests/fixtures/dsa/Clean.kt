package com.example.clean

import java.security.Signature

class Clean {
    fun run() {
        Signature.getInstance("ML-DSA-44")
        // ML-DSA ends in "DSA" but is not DSA.
        Signature.getInstance("SHA512withML-DSA")
    }
}
