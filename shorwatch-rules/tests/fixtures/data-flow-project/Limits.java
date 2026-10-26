package com.example.billing;

import java.security.Signature;

/**
 * Not followed: a call through an interface could reach any implementation,
 * which only the compiled class hierarchy knows. No findings here, although
 * SHA1withRSA reaches Signature.getInstance at run time.
 */
public class Limits {
    interface Signer {
        byte[] sign(byte[] data, String algorithm) throws Exception;
    }

    static class JcaSigner implements Signer {
        public byte[] sign(byte[] data, String algorithm) throws Exception {
            Signature signer = Signature.getInstance(algorithm);
            signer.update(data);
            return signer.sign();
        }
    }

    byte[] use(Signer signer, byte[] data) throws Exception {
        return signer.sign(data, "SHA1withRSA");
    }
}
