package com.example.auth

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm

class Clean {
    fun symmetricOnly(jws: JWSAlgorithm, jwe: JWEAlgorithm): Boolean =
        jws in JWSAlgorithm.Family.HMAC_SHA && jwe in JWEAlgorithm.Family.AES_GCM_KW
}
