package com.example.gateway

import javax.net.ssl.SSLParameters
import org.eclipse.jetty.util.ssl.SslContextFactory

class Clean {
    fun tls13(): SSLParameters = SSLParameters().apply {
        // TLS 1.3 suites carry no key exchange; the group below is post-quantum only.
        cipherSuites = arrayOf("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")
        protocols = arrayOf("TLSv1.3")
        System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768")
        setNamedGroups(arrayOf("X25519MLKEM768"))
        // A group name stored under another key is not the JVM's setting.
        System.setProperty("app.curve", "x25519")
        System.setProperty("app.name", "TLS_RSA gateway")
        // Looks like an OpenSSL suite name, but is not one.
        System.setProperty("app.padding", "AES256-SHAKE")
    }

    fun hardening(factory: SslContextFactory.Server, suites: MutableList<String>) {
        // Suites named to forbid them are not in use.
        factory.setExcludeCipherSuites("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "SSL_RSA_WITH_DES_CBC_SHA")
        factory.addExcludeCipherSuites(*listOf("TLS_DHE_RSA_WITH_AES_128_CBC_SHA").toTypedArray())
        suites.remove("TLS_RSA_WITH_AES_128_GCM_SHA256")
    }
}
