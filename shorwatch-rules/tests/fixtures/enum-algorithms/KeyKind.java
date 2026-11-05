package com.example.keys;

/** The algorithm of each kind of key lives here, not at the call site. */
public enum KeyKind {
    LEGACY("RSA"),
    SIGNING("EC"),
    SESSION("AES");

    private final String jceName;

    KeyKind(String jceName) {
        this.jceName = jceName;
    }

    public String getJceName() {
        return jceName;
    }
}
