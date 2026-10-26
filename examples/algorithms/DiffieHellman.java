import javax.crypto.KeyAgreement;

/** Finite-field Diffie-Hellman: broken by Shor. Migrate to ML-KEM. */
class DiffieHellman {
    KeyAgreement agreement() throws Exception {
        return KeyAgreement.getInstance("DH");
    }
}
