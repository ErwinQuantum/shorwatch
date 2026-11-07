package com.example.gateway

import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import java.io.File
import javax.net.ssl.SSLParameters
import org.eclipse.jetty.util.ssl.SslContextFactory

private const val LEGACY_SUITE = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

/** TLS 1.2 suites pinned in code: every one negotiates a classical key exchange. */
class Vulnerable {
    fun jsse(): SSLParameters = SSLParameters().apply {
        cipherSuites = arrayOf(
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", LEGACY_SUITE,
        )
        setNamedGroups(arrayOf("secp256r1", "ffdhe2048"))
    }

    fun netty(cert: File, key: File): SslContext =
        SslContextBuilder.forServer(cert, key)
            .ciphers(listOf("ECDHE-RSA-AES256-GCM-SHA384"))
            .build()

    fun jetty(factory: SslContextFactory.Server) {
        factory.setIncludeCipherSuites("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
    }

    /** OpenSSL names: static RSA has no key-exchange prefix, static ECDH does. */
    fun openSsl(builder: SslContextBuilder): SslContextBuilder =
        builder.ciphers(listOf("AES128-GCM-SHA256:AES256-SHA", "ECDH-RSA-AES128-SHA"))

    fun jvmWide() {
        System.setProperty("jdk.tls.namedGroups", "x25519,secp256r1")
    }
}
