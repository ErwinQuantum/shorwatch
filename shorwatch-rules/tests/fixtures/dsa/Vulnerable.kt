package com.example.legacy

import java.security.KeyPairGenerator
import java.security.Signature
import org.bouncycastle.crypto.signers.DSASigner

class Vulnerable {
    fun generate(): Any =
        KeyPairGenerator.getInstance("DSA").also { it.initialize(2048) }.generateKeyPair()

    fun signer(): Signature = Signature.getInstance("SHA256withDSA")

    fun bouncyCastle(): Any = DSASigner()
}
