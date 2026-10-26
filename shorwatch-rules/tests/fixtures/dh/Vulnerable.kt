package com.example.legacy

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import javax.crypto.KeyAgreement
import javax.crypto.spec.DHParameterSpec
import org.bouncycastle.crypto.agreement.DHBasicAgreement

object Algorithms {
    const val KEY_AGREEMENT = "DiffieHellman"
}

class Vulnerable {
    fun generate(p: BigInteger, g: BigInteger): KeyPair {
        val generator = KeyPairGenerator.getInstance("DH")
        generator.initialize(DHParameterSpec(p, g))
        return generator.generateKeyPair()
    }

    fun agree(mine: KeyPair, theirs: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance(Algorithms.KEY_AGREEMENT)
        agreement.init(mine.private)
        agreement.doPhase(theirs, true)
        return agreement.generateSecret()
    }

    fun lightweight(): Any = DHBasicAgreement()
}
