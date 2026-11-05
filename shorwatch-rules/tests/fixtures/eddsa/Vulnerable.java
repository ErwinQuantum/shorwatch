package com.example.legacy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import net.i2p.crypto.eddsa.EdDSAEngine;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public class Vulnerable {
    KeyPair generate() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    byte[] sign(KeyPair pair, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("EdDSA");
        signature.initSign(pair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    Object bouncyCastle() {
        return new Ed25519Signer();
    }

    Object ssh() {
        return new EdDSAEngine();
    }

    // The OIDs, which the JDK also accepts as names.
    void oids() throws Exception {
        Signature.getInstance("1.3.101.112");
        Signature.getInstance("OID.1.3.101.113");
    }
}
