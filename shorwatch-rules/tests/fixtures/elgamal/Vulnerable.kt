package com.example.legacy

import java.security.KeyPairGenerator
import javax.crypto.Cipher
import org.bouncycastle.crypto.engines.ElGamalEngine
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator

class Vulnerable {
    fun provider(): Cipher {
        KeyPairGenerator.getInstance("ElGamal", "BC")
        return Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC")
    }

    fun lightweight(): Any {
        ElGamalKeyPairGenerator()
        return ElGamalEngine()
    }
}
