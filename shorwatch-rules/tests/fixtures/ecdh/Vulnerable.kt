package com.example.legacy

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import org.bouncycastle.crypto.agreement.ECDHCUnifiedAgreement
import org.bouncycastle.crypto.agreement.X25519Agreement

class Vulnerable {
    fun ecdh(mine: KeyPair, theirs: PublicKey): ByteArray =
        with(KeyAgreement.getInstance("ECDH")) {
            init(mine.private)
            doPhase(theirs, true)
            generateSecret()
        }

    fun x25519(): KeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair()

    fun xdh(mine: KeyPair, theirs: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("XDH", "SunEC")
        agreement.init(mine.private)
        agreement.doPhase(theirs, true)
        return agreement.generateSecret()
    }

    fun ecies(): Cipher = Cipher.getInstance("ECIESwithAES-CBC")

    fun lightweight(): Any = X25519Agreement()

    fun unified(): Any = ECDHCUnifiedAgreement()
}
