package com.example.transfer;

import java.security.KeyPair;
import java.util.Date;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

/** Encrypting and signing files for a partner over SFTP, the classic PGP setup. */
public class Vulnerable {
    PGPKeyPair signingKey(KeyPair keys) throws Exception {
        return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keys, new Date());
    }

    PGPKeyPair agreementKey(KeyPair keys) throws Exception {
        return new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, keys, new Date());
    }

    /** Two findings: ECDSA and SHA-1. */
    JcaPGPContentSignerBuilder signer() {
        return new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA, HashAlgorithmTags.SHA1);
    }

    JcePGPDataEncryptorBuilder legacyEncryption() {
        new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES);
        return new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128);
    }
}
