package com.example.pki

import java.security.KeyPair
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

class Clean {
    fun postQuantum(keys: KeyPair): ContentSigner = JcaContentSignerBuilder("ML-DSA-65").build(keys.private)

    // Unknown statically: left to future data-flow analysis.
    fun configured(keys: KeyPair, algorithm: String): ContentSigner =
        JcaContentSignerBuilder(algorithm).build(keys.private)
}
