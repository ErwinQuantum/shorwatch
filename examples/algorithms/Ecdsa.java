import java.security.Signature;

/** ECDSA: forgeable with Shor. Migrate to ML-DSA. */
class Ecdsa {
    Signature signer() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }
}
