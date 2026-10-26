package com.example.auth;

import io.jsonwebtoken.Jwts;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/** Dual-signed tokens during the migration window. */
public class Hybrid {
    Object classical() {
        return Jwts.SIG.ES256;
    }
}
