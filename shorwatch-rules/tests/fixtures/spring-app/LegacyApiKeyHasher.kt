package com.example.authserver.legacy

import java.security.MessageDigest

private const val DIGEST = "SHA-1"

/** API keys from the v1 platform were stored as SHA-1 digests. */
object LegacyApiKeyHasher : (String) -> String {
    override fun invoke(apiKey: String): String =
        MessageDigest.getInstance(DIGEST)
            .digest(apiKey.toByteArray())
            .joinToString("") { "%02x".format(it) }
}
