package com.example.auth

import io.jsonwebtoken.Jwts
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner

/** Dual-signed tokens during the migration window. */
class Hybrid {
    fun classical(): Any = Jwts.SIG.ES256
}
