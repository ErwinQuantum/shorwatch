import java.security.Signature;

/** EdDSA (Ed25519): forgeable with Shor. Migrate to ML-DSA. */
class EdDsa {
    Signature signer() throws Exception {
        return Signature.getInstance("Ed25519");
    }
}
