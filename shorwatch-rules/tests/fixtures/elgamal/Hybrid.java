package com.example.migrating;

import javax.crypto.Cipher;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

public class Hybrid {
    Cipher legacyDecryptOnly() throws Exception {
        return Cipher.getInstance("ElGamal/None/OAEPWithSHA-256AndMGF1Padding");
    }
}
