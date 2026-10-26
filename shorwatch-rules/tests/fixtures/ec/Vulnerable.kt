package com.example.legacy

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class Vulnerable {
    /** Key generation alone: ECDH or ECDSA? Reported as generic ECC. */
    fun generate(): KeyPair {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        return generator.generateKeyPair()
    }

    /** The signature itself is unambiguous and gets the ECDSA finding. */
    fun signer(): Signature = Signature.getInstance("SHA256withECDSA")
}
