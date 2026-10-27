package com.example.billing;

import java.security.KeyPairGenerator;

/** Reported here: the algorithm comes from Providers, through Keys.provider(). */
public class DefaultKeyProvider implements KeyProvider {
    @Override
    public KeyPairGenerator generator(String algorithm) throws Exception {
        return KeyPairGenerator.getInstance(algorithm);
    }
}
