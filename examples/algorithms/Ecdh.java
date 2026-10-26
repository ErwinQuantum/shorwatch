import javax.crypto.KeyAgreement;

/** ECDH and X25519: broken by Shor. Migrate to ML-KEM, e.g. hybrid X25519MLKEM768. */
class Ecdh {
    KeyAgreement ecdh() throws Exception {
        return KeyAgreement.getInstance("ECDH");
    }

    KeyAgreement x25519() throws Exception {
        return KeyAgreement.getInstance("X25519");
    }
}
