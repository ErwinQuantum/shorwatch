package com.example.legacy

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import net.i2p.crypto.eddsa.EdDSAEngine
import org.bouncycastle.crypto.signers.Ed25519Signer

class Vulnerable {
    fun generate(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    fun sign(pair: KeyPair, data: ByteArray): ByteArray =
        Signature.getInstance("EdDSA").let { signature ->
            signature.initSign(pair.private)
            signature.update(data)
            signature.sign()
        }

    fun bouncyCastle(): Any = Ed25519Signer()

    fun ssh(): Any = EdDSAEngine()
}
