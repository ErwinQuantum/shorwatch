package com.example.pki;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A self-signed certificate, the way most projects issue test or internal CAs. */
public class Vulnerable {
    private static final String LEGACY = "SHA1withRSA";

    X509Certificate selfSigned(KeyPair keys, Date from, Date to) throws Exception {
        X500Name name = new X500Name("CN=internal-ca");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, from, to, name, keys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    ContentSigner ecdsa(KeyPair keys) throws Exception {
        return new JcaContentSignerBuilder("SHA384withECDSA").build(keys.getPrivate());
    }

    ContentSigner ed25519(KeyPair keys) throws Exception {
        return new JcaContentSignerBuilder("Ed25519").build(keys.getPrivate());
    }

    /** Two findings: SHA-1 and RSA. */
    ContentSigner legacy(KeyPair keys) throws Exception {
        return new JcaContentSignerBuilder(LEGACY).build(keys.getPrivate());
    }

    Object lightweight() {
        return new BcECContentSignerBuilder(null, null);
    }
}
