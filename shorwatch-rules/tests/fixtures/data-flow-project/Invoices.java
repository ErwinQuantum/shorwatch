package com.example.billing;

import java.security.MessageDigest;
import java.security.Signature;

public class Invoices {
    private final CryptoUtil crypto = new CryptoUtil();

    /** Reported in CryptoUtil, where the algorithm is used. */
    byte[] sign(byte[] data) throws Exception {
        return CryptoUtil.sign(data, "SHA1withRSA");
    }

    void encrypt() throws Exception {
        crypto.cipher("RSA/ECB/OAEPPadding");
    }

    /** RSA, SHA-1 and ECDSA: what forPartner can return. */
    Signature partnerSigner(String tier) throws Exception {
        return Signature.getInstance(Algorithms.forPartner(tier));
    }

    byte[] legacyChecksum(byte[] data) throws Exception {
        return MessageDigest.getInstance(Algorithms.identity("SHA-1")).digest(data);
    }

    /** Reported in Checksums, through its constructor. */
    Checksums partnerChecksums() {
        return new Checksums("SHA-1");
    }
}
