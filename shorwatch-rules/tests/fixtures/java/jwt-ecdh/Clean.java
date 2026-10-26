package com.example.auth;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import io.jsonwebtoken.Jwts;

public class Clean {
    /** Symmetric key wrapping with a 256-bit key: fine. */
    Object symmetric() {
        Jwts.KEY.A256GCMKW.key().build();
        return new Object[] {JWEAlgorithm.DIR, EncryptionMethod.A256GCM};
    }
}
