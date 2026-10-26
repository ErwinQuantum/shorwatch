package com.example.payments.auth;

import com.nimbusds.jose.JWSAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Webhook tokens: the algorithm comes from application.yml. */
@Component
public class TokenSigner {
    @Value("${payments.webhooks.signing-algorithm}")
    private String algorithm;

    JWSAlgorithm algorithm() {
        return JWSAlgorithm.parse(algorithm);
    }
}
