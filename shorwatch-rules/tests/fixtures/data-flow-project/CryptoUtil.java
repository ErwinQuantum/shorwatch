package com.example.billing;

import java.security.Signature;
import javax.crypto.Cipher;

/** A shared helper: the algorithms come from its callers in other files. */
public class CryptoUtil {
    public static byte[] sign(byte[] data, String algorithm) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.update(data);
        return signer.sign();
    }

    public Cipher cipher(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }
}
