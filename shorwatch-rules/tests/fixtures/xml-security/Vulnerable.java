package com.example.saml;

import java.util.Collections;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;

/** Signing and encrypting SAML assertions. */
public class Vulnerable {
    SignedInfo signedInfo(XMLSignatureFactory factory) throws Exception {
        return factory.newSignedInfo(
                factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
                Collections.singletonList(factory.newReference("", factory.newDigestMethod(DigestMethod.SHA256, null))));
    }

    /** Two findings: SHA-1 digest and ECDSA with SHA-1. */
    Object legacy(XMLSignatureFactory factory) throws Exception {
        factory.newDigestMethod(DigestMethod.SHA1, null);
        return factory.newSignatureMethod(SignatureMethod.ECDSA_SHA1, null);
    }

    String santuario() {
        return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
    }

    XMLCipher keyTransport() throws Exception {
        XMLCipher.getInstance(XMLCipher.AES_128);
        return XMLCipher.getInstance(XMLCipher.RSA_OAEP);
    }
}
