package com.example.saml;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import org.apache.xml.security.encryption.XMLCipher;

public class Clean {
    Object[] symmetric() {
        // HMAC signatures, SHA-2 digests and AES-256 are fine.
        return new Object[] {SignatureMethod.HMAC_SHA256, DigestMethod.SHA256, XMLCipher.AES_256_GCM};
    }
}
