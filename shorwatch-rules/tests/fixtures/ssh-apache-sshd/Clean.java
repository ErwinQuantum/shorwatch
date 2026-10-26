package com.example.sftp;

import java.util.List;
import org.apache.sshd.common.kex.BuiltinDHFactories;

public class Clean {
    /** Hybrid post-quantum key exchange only. */
    List<Object> keyExchange() {
        return List.of(BuiltinDHFactories.mlkem768x25519, BuiltinDHFactories.sntrup761x25519);
    }
}
