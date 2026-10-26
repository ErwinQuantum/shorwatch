import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

/** RSA: broken by Shor. Migrate to ML-KEM (encryption) / ML-DSA (signatures). */
class Rsa {
    Object keys() throws Exception {
        return KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    Cipher cipher() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
}
