package com.example.wallet;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/** Device-bound keys in the Android Keystore. */
public class Vulnerable {
    KeyPair signingKey() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        generator.initialize(new KeyGenParameterSpec.Builder("signing", KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        return generator.generateKeyPair();
    }

    KeyPair wrappingKey() throws Exception {
        return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").generateKeyPair();
    }
}
