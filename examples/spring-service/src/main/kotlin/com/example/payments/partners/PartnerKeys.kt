package com.example.payments.partners

import com.nimbusds.jose.JWSAlgorithm.ES384
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.springframework.stereotype.Component

/**
 * Keys for partner integrations, written in Kotlin: the same JVM libraries,
 * so the same rules apply.
 */
@Component
class PartnerKeys {
    /** Partners sign their callbacks with ES384. */
    val acceptedAlgorithm = ES384

    fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()
}
