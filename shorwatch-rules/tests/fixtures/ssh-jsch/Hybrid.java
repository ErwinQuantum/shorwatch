package com.example.deploy;

import com.jcraft.jsch.JSch;

/** OpenSSH 9.9's hybrid ML-KEM key exchange preferred, classical kept as fallback. */
public class Hybrid {
    void configure() {
        JSch.setConfig("kex", "mlkem768x25519-sha256,curve25519-sha256");
    }
}
