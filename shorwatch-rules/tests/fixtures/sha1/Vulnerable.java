package com.example.legacy;

import com.google.common.hash.Hashing;
import java.security.MessageDigest;
import java.security.Signature;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;

public class Vulnerable {
    byte[] jca(byte[] data) throws Exception {
        MessageDigest.getInstance("SHA");
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    /** Two findings: SHA-1 and RSA are separate problems. */
    Signature legacySignature() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }

    String libraries(byte[] data) {
        new SHA1Digest();
        Hashing.sha1();
        return DigestUtils.sha1Hex(data);
    }

    /** The JDK takes older aliases and OIDs as names too. */
    void aliases() throws Exception {
        MessageDigest.getInstance("1.3.14.3.2.26");
        Signature.getInstance("DSAWithSHA1");
        Signature.getInstance("1.2.840.113549.1.1.5");
    }

    /** Commons Codec's deprecated names, and the algorithm constant. */
    Object deprecatedCodec(byte[] data) {
        DigestUtils.shaHex(data);
        return MessageDigestAlgorithms.SHA_1;
    }

    /** Spring Security password encoders over a bare SHA-1. */
    Object passwordEncoders() {
        new MessageDigestPasswordEncoder("SHA-1");
        return new LdapShaPasswordEncoder();
    }

    /** XML Signature algorithms written as URIs; HMAC is deliberately left out. */
    String[] xmlUris() {
        return new String[] {
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
        };
    }
}
