package com.example.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** No `app.legacy.*` key is set: the default is what runs. */
@ConfigurationProperties("app.legacy")
public class LegacyProperties {
    private String digest = "SHA-1";

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }
}
