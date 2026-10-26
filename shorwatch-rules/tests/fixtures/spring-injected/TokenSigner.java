package com.example.tokens;

import com.nimbusds.jose.JWSAlgorithm;
import io.jsonwebtoken.SignatureAlgorithm;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Algorithms come from configuration, not from the code. */
@Component
public class TokenSigner {
    @Value("${jwt.signingAlgorithm}")
    private String signingAlgorithm;

    /** Not set in any config file: the default decides. */
    @Value("${jwt.legacy-algorithm:ES384}")
    private String legacyAlgorithm;

    /** Not set anywhere and no default: unknown, so no finding. */
    @Value("${jwt.partner-algorithm}")
    private String partnerAlgorithm;

    JWSAlgorithm current() {
        // HS256 in the default profile, RS256 in prod: reported.
        return JWSAlgorithm.parse(signingAlgorithm);
    }

    SignatureAlgorithm legacy() {
        return SignatureAlgorithm.forName(this.legacyAlgorithm);
    }

    JWSAlgorithm partner() {
        return JWSAlgorithm.parse(partnerAlgorithm);
    }

    /** 128 comes from config: reported, but no fix at the use site. */
    SecretKey dataKey(@Value("${crypto.key-size}") int bits) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(bits);
        return generator.generateKey();
    }
}
