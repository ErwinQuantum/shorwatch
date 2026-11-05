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

    // The OIDs, which the JDK also accepts as names.
    fun oids() {
        Signature.getInstance("1.3.101.112")
        Signature.getInstance("OID.1.3.101.113")
    }
}
