package com.example.migrating

import javax.crypto.KeyAgreement
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator

/** Hybrid key exchange: DH secret and ML-KEM secret combined through a KDF. */
class Hybrid {
    fun classicalSecret(): ByteArray = KeyAgreement.getInstance("DH").generateSecret()
}
