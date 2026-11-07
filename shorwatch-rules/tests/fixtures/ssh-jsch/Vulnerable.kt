package com.example.deploy

import com.jcraft.jsch.HostKey
import com.jcraft.jsch.JSch
import com.jcraft.jsch.KeyPair
import com.jcraft.jsch.Session

/** Deploying over SSH with JSch. */
class Vulnerable {
    fun deployKey(jsch: JSch): KeyPair = KeyPair.genKeyPair(jsch, KeyPair.RSA, 3072)

    fun connect(jsch: JSch, host: String): Session {
        // Three findings: DH and ECDH key exchange, ECDSA host keys.
        JSch.setConfig("kex", "ecdh-sha2-nistp256,diffie-hellman-group14-sha256")
        // The declared type tells what `getSession` returns: return types of
        // library methods are not known without compiling.
        val session: Session = jsch.getSession("deploy", host, 22)
        session.setConfig("server_host_key", "ecdsa-sha2-nistp256")
        return session
    }

    fun hostKeyTypes(hostKey: HostKey): Boolean =
        // Comparing a host key type names the algorithm too.
        hostKey.type == HostKey.SSHRSA || hostKey.type == HostKey.SSHDSS ||
            hostKey.type == HostKey.ECDSA256 || hostKey.type == HostKey.ED25519
}
