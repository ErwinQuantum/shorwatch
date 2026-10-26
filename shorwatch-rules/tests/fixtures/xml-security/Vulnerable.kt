package com.example.saml

import javax.xml.crypto.dsig.CanonicalizationMethod
import javax.xml.crypto.dsig.DigestMethod
import javax.xml.crypto.dsig.SignatureMethod
import javax.xml.crypto.dsig.SignedInfo
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec
import org.apache.xml.security.encryption.XMLCipher
import org.apache.xml.security.signature.XMLSignature

/** Signing and encrypting SAML assertions. */
class Vulnerable {
    fun signedInfo(factory: XMLSignatureFactory): SignedInfo = factory.newSignedInfo(
        factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, null as C14NMethodParameterSpec?),
        factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
        listOf(factory.newReference("", factory.newDigestMethod(DigestMethod.SHA256, null))),
    )

    /** Two findings: SHA-1 digest and ECDSA with SHA-1. */
    fun legacy(factory: XMLSignatureFactory): Any {
        factory.newDigestMethod(DigestMethod.SHA1, null)
        return factory.newSignatureMethod(SignatureMethod.ECDSA_SHA1, null)
    }

    fun santuario(): String = XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256

    fun keyTransport(): XMLCipher {
        XMLCipher.getInstance(XMLCipher.AES_128)
        return XMLCipher.getInstance(XMLCipher.RSA_OAEP)
    }
}
