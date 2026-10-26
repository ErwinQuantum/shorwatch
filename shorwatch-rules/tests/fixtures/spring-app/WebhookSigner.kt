package com.example.authserver.webhooks

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

private const val MAC_ALGORITHM = "HmacSHA256"

/** Outgoing webhooks: HMAC signatures and payload encryption. */
class WebhookSigner {
    fun sign(secret: ByteArray, payload: ByteArray): ByteArray =
        Mac.getInstance(MAC_ALGORITHM).apply { init(SecretKeySpec(secret, MAC_ALGORITHM)) }
            .doFinal(payload)

    fun payloadKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(128)
        return generator.generateKey()
    }

    fun payloadCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
}
