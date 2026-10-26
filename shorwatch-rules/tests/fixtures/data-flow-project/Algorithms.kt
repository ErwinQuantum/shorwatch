package com.example.billing.kt

/** Algorithm names chosen in one place, used elsewhere. */
object Algorithms {
    fun forPartner(tier: String): String = if (tier == "legacy") "SHA1withRSA" else "SHA256withECDSA"

    fun identity(algorithm: String): String = algorithm
}
