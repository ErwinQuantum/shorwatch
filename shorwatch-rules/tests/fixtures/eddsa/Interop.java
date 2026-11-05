package com.example.legacy;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

/** EdDSA where SSH, OpenPGP and XML Signature name it. */
public class Interop {
    void ssh(JSch jsch) throws Exception {
        jsch.setConfig("server_host_key", "ssh-ed25519,ssh-ed448");
        KeyPair.genKeyPair(jsch, KeyPair.ED25519);
    }

    int openPgp() {
        return PublicKeyAlgorithmTags.EDDSA_LEGACY;
    }

    String xml() {
        return XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED25519;
    }
}
