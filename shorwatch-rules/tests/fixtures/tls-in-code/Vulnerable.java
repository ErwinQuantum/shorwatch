package com.example.gateway;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.io.File;
import java.util.List;
import javax.net.ssl.SSLParameters;
import org.eclipse.jetty.util.ssl.SslContextFactory;

/** TLS 1.2 suites pinned in code: every one negotiates a classical key exchange. */
public class Vulnerable {
    private static final String LEGACY_SUITE = "TLS_RSA_WITH_3DES_EDE_CBC_SHA";

    SSLParameters jsse() {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", LEGACY_SUITE,
        });
        params.setNamedGroups(new String[] {"secp256r1", "ffdhe2048"});
        return params;
    }

    SslContext netty(File cert, File key) throws Exception {
        return SslContextBuilder.forServer(cert, key)
                .ciphers(List.of("ECDHE-RSA-AES256-GCM-SHA384"))
                .build();
    }

    void jetty(SslContextFactory.Server factory) {
        factory.setIncludeCipherSuites("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
    }

    /** OpenSSL names: static RSA has no key-exchange prefix, static ECDH does. */
    SslContextBuilder openSsl(SslContextBuilder builder) {
        return builder.ciphers(List.of("AES128-GCM-SHA256:AES256-SHA", "ECDH-RSA-AES128-SHA"));
    }

    void jvmWide() {
        System.setProperty("jdk.tls.namedGroups", "x25519,secp256r1");
    }
}
