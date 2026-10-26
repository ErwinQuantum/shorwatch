package com.example.clean

import java.security.KeyPairGenerator

class Clean {
    fun run() {
        KeyPairGenerator.getInstance("ML-DSA")
        // Not "EC": only the exact name is ambiguous.
        KeyPairGenerator.getInstance("ECX")
        // Other types' nested builders are not Nimbus' `ECKey.Builder`.
        Settings.Builder().build()
        Builder()
    }

    class Builder
}
