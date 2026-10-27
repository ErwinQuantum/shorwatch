package com.example.billing;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Providers {
    /** A chained call: provider() returns the interface. */
    KeyPair partnerKeys() throws Exception {
        return Keys.provider().generator("RSA").generateKeyPair();
    }

    /** A constant of another file, used here and passed to the provider. */
    KeyPair agreementKeys() throws Exception {
        KeyPairGenerator.getInstance(KeyTypes.EC);
        return Keys.provider().generator(KeyTypes.EC).generateKeyPair();
    }

    /** A longer chain: each call is typed from the one before. */
    KeyPair archiveKeys() throws Exception {
        return Registry.registry().provider().generator("DSA").generateKeyPair();
    }

    /** No type written: the variable takes provider()'s return type. */
    KeyPair escrowKeys() throws Exception {
        var provider = Keys.provider();
        return provider.generator("DH").generateKeyPair();
    }
}
