package com.example.auth;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

public class Clean {
    boolean symmetricOnly(JWSAlgorithm jws, JWEAlgorithm jwe) {
        return JWSAlgorithm.Family.HMAC_SHA.contains(jws) && JWEAlgorithm.Family.AES_GCM_KW.contains(jwe);
    }
}
