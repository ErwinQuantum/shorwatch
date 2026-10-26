package com.example.legacy;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import org.bouncycastle.crypto.signers.ECDSASigner;

public class Vulnerable {
    private static final String P1363 = "SHA384withECDSAinP1363Format";

    byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    Signature jose() throws Exception {
        return Signature.getInstance(P1363);
    }

    Object bouncyCastle() throws Exception {
        KeyPairGenerator.getInstance("ECDSA", "BC");
        return new ECDSASigner();
    }
}
