package com.example.billing;

/** Algorithm names chosen in one place, used elsewhere. */
public final class Algorithms {
    static String forPartner(String tier) {
        return "legacy".equals(tier) ? "SHA1withRSA" : "SHA256withECDSA";
    }

    static String identity(String algorithm) {
        return algorithm;
    }
}
