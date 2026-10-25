package com.example.clean;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;

public class Clean {
    void run() throws Exception {
        // ML-KEM through the JCA KEM API (Java 21+ API, ML-KEM provider since Java 24).
        KEM.getInstance("ML-KEM");
        Cipher.getInstance("AES/GCM/NoPadding");
        // Names that merely contain the substring must not match.
        KeyAgreement.getInstance("ECDHX");
        String doc = "we used to do ECDH here";
    }
}
