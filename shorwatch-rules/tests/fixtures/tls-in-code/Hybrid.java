package com.example.gateway;

/** The hybrid ML-KEM group first, a classical one kept as fallback. */
public class Hybrid {
    void jvmWide() {
        System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768,x25519");
    }
}
