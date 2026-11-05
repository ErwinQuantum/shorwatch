package com.example.legacy

import com.jcraft.jsch.JSch
import com.jcraft.jsch.KeyPair
import org.apache.xml.security.signature.XMLSignature
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags

/** EdDSA where SSH, OpenPGP and XML Signature name it. */
class Interop {
    fun ssh(jsch: JSch) {
        jsch.setConfig("server_host_key", "ssh-ed25519,ssh-ed448")
        KeyPair.genKeyPair(jsch, KeyPair.ED25519)
    }

    fun openPgp(): Int = PublicKeyAlgorithmTags.EDDSA_LEGACY

    fun xml(): String = XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED25519
}
