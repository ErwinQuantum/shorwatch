package com.example.migrating

import javax.crypto.Cipher
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec

class Hybrid {
    fun legacyDecryptOnly(): Cipher =
        Cipher.getInstance("ElGamal/None/OAEPWithSHA-256AndMGF1Padding")
}
