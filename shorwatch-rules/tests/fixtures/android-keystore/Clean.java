package com.example.wallet;

import android.security.keystore.KeyProperties;
import javax.crypto.KeyGenerator;

public class Clean {
    Object symmetricKey() throws Exception {
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    }
}
