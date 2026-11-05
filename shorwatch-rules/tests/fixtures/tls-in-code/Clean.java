package com.example.gateway;

import java.util.List;
import javax.net.ssl.SSLParameters;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public class Clean {
    SSLParameters tls13() {
        SSLParameters params = new SSLParameters();
        // TLS 1.3 suites carry no key exchange; the group below is post-quantum only.
        params.setCipherSuites(new String[] {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"});
        params.setProtocols(new String[] {"TLSv1.3"});
        System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768");
        System.setProperty("app.name", "TLS_RSA gateway");
        // Looks like an OpenSSL suite name, but is not one.
        System.setProperty("app.padding", "AES256-SHAKE");
        return params;
    }

    void hardening(SslContextFactory.Server factory, List<String> suites) {
        // Suites named to forbid them are not in use.
        factory.setExcludeCipherSuites("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "SSL_RSA_WITH_DES_CBC_SHA");
        factory.addExcludeCipherSuites(List.of("TLS_DHE_RSA_WITH_AES_128_CBC_SHA").toArray(new String[0]));
        suites.remove("TLS_RSA_WITH_AES_128_GCM_SHA256");
    }
}
