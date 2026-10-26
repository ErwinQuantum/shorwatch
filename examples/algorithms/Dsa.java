import java.security.Signature;

/** DSA: forgeable with Shor (and withdrawn by FIPS 186-5). Migrate to ML-DSA. */
class Dsa {
    Signature signer() throws Exception {
        return Signature.getInstance("SHA256withDSA");
    }
}
