package com.example.auth;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import io.jsonwebtoken.Jwts;

public class Clean {
    Object strong() {
        Jwts.ENC.A256GCM.key().build();
        Jwts.KEY.A256KW.key().build();
        return new Object[] {JWEAlgorithm.A256GCMKW, EncryptionMethod.A256CBC_HS512};
    }
}
