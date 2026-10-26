package com.example.wallet

import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator

class Clean {
    fun symmetricKey(): Any = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
}
