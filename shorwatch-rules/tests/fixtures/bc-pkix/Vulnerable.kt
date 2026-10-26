package com.example.pki

import java.math.BigInteger
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.bc.BcECContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

private const val LEGACY = "SHA1withRSA"

/** A self-signed certificate, the way most projects issue test or internal CAs. */
class Vulnerable {
    fun selfSigned(keys: KeyPair, from: Date, to: Date): X509Certificate {
        val name = X500Name("CN=internal-ca")
        val builder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, from, to, name, keys.public)
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keys.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    fun ecdsa(keys: KeyPair): ContentSigner = JcaContentSignerBuilder("SHA384withECDSA").build(keys.private)

    fun ed25519(keys: KeyPair): ContentSigner = JcaContentSignerBuilder("Ed25519").build(keys.private)

    /** Two findings: SHA-1 and RSA. */
    fun legacy(keys: KeyPair): ContentSigner = JcaContentSignerBuilder(LEGACY).build(keys.private)

    fun lightweight(): Any = BcECContentSignerBuilder(null, null)
}
