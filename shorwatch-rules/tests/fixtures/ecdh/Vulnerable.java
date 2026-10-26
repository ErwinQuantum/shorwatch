package com.example.legacy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;

public class Vulnerable {
    byte[] ecdh(KeyPair mine, PublicKey theirs) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(mine.getPrivate());
        agreement.doPhase(theirs, true);
        return agreement.generateSecret();
    }

    KeyPair x25519() throws Exception {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    byte[] xdh(KeyPair mine, PublicKey theirs) throws Exception {
        var agreement = KeyAgreement.getInstance("XDH", "SunEC");
        agreement.init(mine.getPrivate());
        agreement.doPhase(theirs, true);
        return agreement.generateSecret();
    }

    Cipher ecies() throws Exception {
        return Cipher.getInstance("ECIESwithAES-CBC");
    }

    Object lightweight() {
        return new X25519Agreement();
    }
}
