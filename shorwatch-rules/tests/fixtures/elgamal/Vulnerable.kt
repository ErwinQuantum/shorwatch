package com.example.legacy

import java.security.AlgorithmParameterGenerator
import java.security.KeyPairGenerator
import javax.crypto.Cipher
import org.bouncycastle.crypto.engines.ElGamalEngine
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator
import org.bouncycastle.jce.spec.ElGamalGenParameterSpec
import org.bouncycastle.jce.spec.ElGamalParameterSpec

class Vulnerable {
    fun provider(): Cipher {
        KeyPairGenerator.getInstance("ElGamal", "BC")
        return Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC")
    }

    fun lightweight(): Any {
        ElGamalKeyPairGenerator()
        return ElGamalEngine()
    }

    // The group of the provider-level key generator, and its own generator.
    fun parameters(): Any {
        AlgorithmParameterGenerator.getInstance("ElGamal", "BC")
        ElGamalGenParameterSpec(1024)
        return ElGamalParameterSpec(null, null)
    }
}
