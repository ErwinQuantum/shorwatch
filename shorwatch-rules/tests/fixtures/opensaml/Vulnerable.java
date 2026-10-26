package com.example.sso;

import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

/** SAML identity provider: assertion signing and encryption algorithms. */
public class Vulnerable {
    String signatureAlgorithm() {
        return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
    }

    /** Two findings: ECDSA and SHA-1. */
    String legacySignature() {
        return SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1;
    }

    String[] encryption() {
        return new String[] {
            EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
            EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
        };
    }
}
