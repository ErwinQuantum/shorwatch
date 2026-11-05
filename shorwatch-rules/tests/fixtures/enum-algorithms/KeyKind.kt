package com.example.keys

/** The algorithm of each kind of key lives here, not at the call site. */
enum class KeyKind(val jceName: String) {
    LEGACY("RSA"),
    SIGNING("EC"),
    SESSION("AES"),
}
