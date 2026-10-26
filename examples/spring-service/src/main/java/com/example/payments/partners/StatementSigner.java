package com.example.payments.partners;

import java.security.PrivateKey;
import java.security.Signature;

/** Signs the monthly statements sent to partner banks. */
public class StatementSigner {
    byte[] sign(String partnerTier, byte[] statement, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance(algorithmFor(partnerTier));
        signer.initSign(key);
        signer.update(statement);
        return signer.sign();
    }

    /** Older partners still verify SHA-1 signatures. */
    private static String algorithmFor(String partnerTier) {
        return switch (partnerTier) {
            case "legacy" -> "SHA1withRSA";
            default -> "SHA256withECDSA";
        };
    }
}
