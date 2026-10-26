package com.example.auth

import com.nimbusds.jose.JWSAlgorithm

class Clean {
    fun symmetric(): Any = JWSAlgorithm.HS256
}
