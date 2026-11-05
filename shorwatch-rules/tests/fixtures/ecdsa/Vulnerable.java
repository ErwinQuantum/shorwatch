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

    // The signature OIDs, which the JDK also accepts as names.
    void oids() throws Exception {
        Signature.getInstance("1.2.840.10045.4.3.2");
        Signature.getInstance("OID.1.2.840.10045.4.1");
    }
}
