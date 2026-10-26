package com.example.billing.kt

import java.security.MessageDigest
import java.security.Signature

class Invoices {
    private val crypto: CryptoUtil = CryptoUtil()

    /** Reported in CryptoUtil, where the algorithm is used. */
    fun sign(data: ByteArray): ByteArray = CryptoUtil.sign(data, "SHA1withRSA")

    fun encrypt() {
        crypto.cipher("RSA/ECB/OAEPPadding")
    }

    /** RSA, SHA-1 and ECDSA: what forPartner can return. */
    fun partnerSigner(tier: String): Signature = Signature.getInstance(Algorithms.forPartner(tier))

    fun legacyChecksum(data: ByteArray): ByteArray =
        MessageDigest.getInstance(Algorithms.identity("SHA-1")).digest(data)

    /** Reported in Checksums, through its constructor. */
    fun partnerChecksums(): Checksums = Checksums("SHA-1")
}
