import com.nimbusds.jose.JWSAlgorithm;
import io.jsonwebtoken.Jwts;

/** JWT signatures with RSA or ECDSA: forgeable with Shor. Migrate to ML-DSA for JOSE. */
class Jwt {
    Object nimbus() {
        return JWSAlgorithm.RS256;
    }

    Object jjwt() {
        return Jwts.SIG.ES256;
    }
}
