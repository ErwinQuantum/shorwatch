package com.example.migrating;

import java.security.Signature;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/** Composite signature: Ed25519 alongside ML-DSA. */
public class Hybrid {
    Object signers() throws Exception {
        return new Object[] {Signature.getInstance("Ed25519"), new MLDSASigner()};
    }
}
