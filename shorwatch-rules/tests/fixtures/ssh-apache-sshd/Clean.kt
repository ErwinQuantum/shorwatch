package com.example.sftp

import org.apache.sshd.common.kex.BuiltinDHFactories

class Clean {
    /** Hybrid post-quantum key exchange only. */
    fun keyExchange(): List<Any> = listOf(BuiltinDHFactories.mlkem768x25519, BuiltinDHFactories.sntrup761x25519)
}
