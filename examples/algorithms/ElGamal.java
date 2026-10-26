import org.bouncycastle.crypto.engines.ElGamalEngine;

/** ElGamal: broken by Shor. Migrate to ML-KEM plus an AEAD. */
class ElGamal {
    Object engine() {
        return new ElGamalEngine();
    }
}
