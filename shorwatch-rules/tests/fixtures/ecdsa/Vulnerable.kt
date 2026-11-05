package com.example.legacy

import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import org.bouncycastle.crypto.signers.ECDSASigner

private const val P1363 = "SHA384withECDSAinP1363Format"

class Vulnerable {
    fun sign(key: PrivateKey, data: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(key)
        signature.update(data)
        return signature.sign()
    }

    fun jose(): Signature = Signature.getInstance(P1363)

    fun bouncyCastle(): Any {
        KeyPairGenerator.getInstance("ECDSA", "BC")
        return ECDSASigner()
    }

    // The signature OIDs, which the JDK also accepts as names.
    fun oids() {
        Signature.getInstance("1.2.840.10045.4.3.2")
        Signature.getInstance("OID.1.2.840.10045.4.1")
    }
}
