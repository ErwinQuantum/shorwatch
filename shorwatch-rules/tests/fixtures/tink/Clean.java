package com.example.tokens;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.PredefinedAeadParameters;

public class Clean {
    KeysetHandle aead() throws Exception {
        KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
        return KeysetHandle.generateNew(KeyTemplates.get("XCHACHA20_POLY1305"));
    }
}
