package com.example.jose;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.ec.ECSigner;
import io.fusionauth.jwt.ed.EdDSASigner;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

public class Vulnerable {
    void jose4jSigning(JsonWebSignature jws) {
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_PSS_USING_SHA384);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.EDDSA);
        jws.setAlgorithmHeaderValue("ES384");
    }

    void jose4jEncryption(JsonWebEncryption jwe) throws Exception {
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        jwe.setAlgorithmHeaderValue("ECDH-ES+A128KW");
        jwe.setEncryptionMethodHeaderParameter(
                ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
    }

    void jose4jKeys() throws Exception {
        RsaJwkGenerator.generateJwk(2048);
        EcJwkGenerator.generateJwk(null);
    }

    void fusionAuth(PrivateKey priv, PublicKey pub) {
        RSASigner.newSHA256Signer(priv);
        RSAVerifier.newVerifier(pub);
        ECSigner.newSHA384Signer(priv);
        EdDSASigner.newSigner(priv);
        Algorithm algorithm = Algorithm.PS256;
    }

    void nimbusKeys(String json) throws Exception {
        RSAKey.parse(json);
        ECKey.parse(json);
    }
}
