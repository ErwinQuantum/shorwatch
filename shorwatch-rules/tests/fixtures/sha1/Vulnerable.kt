package com.example.legacy

import com.google.common.hash.Hashing
import java.security.MessageDigest
import java.security.Signature
import org.apache.commons.codec.digest.DigestUtils
import org.bouncycastle.crypto.digests.SHA1Digest

class Vulnerable {
    fun jca(data: ByteArray): ByteArray {
        MessageDigest.getInstance("SHA")
        return MessageDigest.getInstance("SHA-1").digest(data)
    }

    /** Two findings: SHA-1 and RSA are separate problems. */
    fun legacySignature(): Signature = Signature.getInstance("SHA1withRSA")

    fun libraries(data: ByteArray): String {
        SHA1Digest()
        Hashing.sha1()
        return DigestUtils.sha1Hex(data)
    }
}
