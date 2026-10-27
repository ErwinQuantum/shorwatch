package com.example.billing;

public final class Keys {
    private static final KeyProvider PROVIDER = new DefaultKeyProvider();

    static KeyProvider provider() {
        return PROVIDER;
    }
}
