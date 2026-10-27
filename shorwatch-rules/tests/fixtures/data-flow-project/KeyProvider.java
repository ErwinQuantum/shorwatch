package com.example.billing;

import java.security.KeyPairGenerator;

/** A pluggable crypto provider, as frameworks have them. */
public interface KeyProvider {
    KeyPairGenerator generator(String algorithm) throws Exception;
}
