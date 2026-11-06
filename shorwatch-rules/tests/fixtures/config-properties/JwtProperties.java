package com.example.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Bound from `app.jwt.*`; the default below is replaced by application.yml. */
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {
    private String algorithm = "SHA256withECDSA";
    private String keyType;

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }
}
