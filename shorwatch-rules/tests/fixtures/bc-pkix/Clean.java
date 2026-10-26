package com.example.pki;

import java.security.KeyPair;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Clean {
    ContentSigner postQuantum(KeyPair keys) throws Exception {
        return new JcaContentSignerBuilder("ML-DSA-65").build(keys.getPrivate());
    }

    ContentSigner configured(KeyPair keys, String algorithm) throws Exception {
        // Unknown statically: left to future data-flow analysis.
        return new JcaContentSignerBuilder(algorithm).build(keys.getPrivate());
    }
}
