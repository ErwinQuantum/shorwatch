package com.example.auth;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

/** Verifiers that accept whole algorithm families, as CAS and Spring Security do. */
public class Vulnerable {
    boolean signatureAccepted(JWSAlgorithm alg) {
        return JWSAlgorithm.Family.RSA.contains(alg)
                || JWSAlgorithm.Family.EC.contains(alg)
                || JWSAlgorithm.Family.ED.contains(alg);
    }

    boolean keyManagementAccepted(JWEAlgorithm alg) {
        return JWEAlgorithm.Family.RSA.contains(alg) || JWEAlgorithm.Family.ECDH_ES.contains(alg);
    }
}
