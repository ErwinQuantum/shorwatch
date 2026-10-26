package com.example.tokens

import com.nimbusds.jose.JWSAlgorithm
import io.jsonwebtoken.SignatureAlgorithm
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

/** Algorithms come from configuration, not from the code. */
@Component
class TokenSigner(
    @Value("\${jwt.signingAlgorithm}") private val signingAlgorithm: String,
    /** Not set in any config file: the default decides. */
    @Value("\${jwt.legacy-algorithm:ES384}") private val legacyAlgorithm: String,
) {
    /** Not set anywhere and no default: unknown, so no finding. */
    @Value("\${jwt.partner-algorithm}")
    private lateinit var partnerAlgorithm: String

    // HS256 in the default profile, RS256 in prod: reported.
    fun current(): JWSAlgorithm = JWSAlgorithm.parse(signingAlgorithm)

    fun legacy(): SignatureAlgorithm = SignatureAlgorithm.forName(this.legacyAlgorithm)

    fun partner(): JWSAlgorithm = JWSAlgorithm.parse(partnerAlgorithm)

    /** 128 comes from config: reported, but no fix at the use site. */
    fun dataKey(@Value("\${crypto.key-size}") bits: Int): SecretKey =
        KeyGenerator.getInstance("AES").apply { init(bits) }.generateKey()
}
