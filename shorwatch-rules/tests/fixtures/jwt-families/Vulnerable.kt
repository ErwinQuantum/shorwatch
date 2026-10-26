package com.example.auth

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm

/** Verifiers that accept whole algorithm families, as CAS and Spring Security do. */
class Vulnerable {
    fun signatureAccepted(alg: JWSAlgorithm): Boolean =
        JWSAlgorithm.Family.RSA.contains(alg) ||
            JWSAlgorithm.Family.EC.contains(alg) ||
            JWSAlgorithm.Family.ED.contains(alg)

    fun keyManagementAccepted(alg: JWEAlgorithm): Boolean =
        alg in JWEAlgorithm.Family.RSA || alg in JWEAlgorithm.Family.ECDH_ES
}
