package com.example.billing;

import java.security.Signature;

/** A call through an interface reaches its implementation. */
public class Interfaces {
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
