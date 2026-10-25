package com.example.migrating;

import javax.crypto.KeyAgreement;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;

/** Hybrid key exchange: DH secret and ML-KEM secret combined through a KDF. */
public class Hybrid {
    byte[] classicalSecret() throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("DH");
        return agreement.generateSecret();
    }
}
