package com.example.authserver.legacy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.function.Function;

/** API keys from the v1 platform were stored as SHA-1 digests. */
public final class LegacyApiKeyHasher implements Function<String, String> {
    private static final String DIGEST = "SHA-1";

    @Override
    public String apply(String apiKey) {
        try {
            MessageDigest md = MessageDigest.getInstance(DIGEST);
            return HexFormat.of().formatHex(md.digest(apiKey.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
