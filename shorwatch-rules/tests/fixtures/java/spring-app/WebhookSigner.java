package com.example.authserver.webhooks;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** Outgoing webhooks: HMAC signatures and payload encryption. */
public class WebhookSigner {
    private static final String MAC_ALGORITHM = "HmacSHA256";

    byte[] sign(byte[] secret, byte[] payload) throws Exception {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(new SecretKeySpec(secret, MAC_ALGORITHM));
        return mac.doFinal(payload);
    }

    SecretKey payloadKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }

    Cipher payloadCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
