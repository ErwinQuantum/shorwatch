package com.example.legacy;

import com.google.common.hash.Hashing;
import java.security.MessageDigest;
import java.security.Signature;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;

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
}
