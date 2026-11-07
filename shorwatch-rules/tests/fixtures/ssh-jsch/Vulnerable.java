package com.example.deploy;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import com.jcraft.jsch.Session;

/** Deploying over SSH with JSch. */
public class Vulnerable {
    KeyPair deployKey(JSch jsch) throws Exception {
        return KeyPair.genKeyPair(jsch, KeyPair.RSA, 3072);
    }

    Session connect(JSch jsch, String host) throws Exception {
        // Three findings: DH and ECDH key exchange, ECDSA host keys.
        JSch.setConfig("kex", "ecdh-sha2-nistp256,diffie-hellman-group14-sha256");
        Session session = jsch.getSession("deploy", host, 22);
        session.setConfig("server_host_key", "ecdsa-sha2-nistp256");
        return session;
    }

    boolean hostKeyTypes(HostKey hostKey) {
        // Comparing a host key type names the algorithm too.
        return hostKey.type == HostKey.SSHRSA || hostKey.type == HostKey.SSHDSS
                || hostKey.type == HostKey.ECDSA256 || hostKey.type == HostKey.ED25519;
    }
}
