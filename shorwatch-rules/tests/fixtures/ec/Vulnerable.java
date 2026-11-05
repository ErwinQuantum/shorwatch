package com.example.legacy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;

public class Vulnerable {
    /** Key generation alone: ECDH or ECDSA? Reported as generic ECC. */
    KeyPair generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** The signature itself is unambiguous and gets the ECDSA finding. */
    Signature signer() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }

    /** BouncyCastle's own generator, and the SSH host key provider's type. */
    Object lightweight() {
        return new ECKeyPairGenerator();
    }

    void hostKey(SimpleGeneratorHostKeyProvider keys) {
        keys.setAlgorithm("EC");
        Object algorithm = KeyUtils.EC_ALGORITHM;
    }
}
