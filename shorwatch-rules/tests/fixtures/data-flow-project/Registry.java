package com.example.billing;

/** Two calls away from the provider: Registry.registry().provider(). */
public final class Registry {
    private static final Registry INSTANCE = new Registry();

    static Registry registry() {
        return INSTANCE;
    }

    KeyProvider provider() {
        return Keys.provider();
    }
}
