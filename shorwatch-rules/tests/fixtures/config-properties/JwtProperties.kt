package com.example.config

import org.springframework.boot.context.properties.ConfigurationProperties

/** Bound from `app.jwt.*`; the default below is replaced by application.yml. */
@ConfigurationProperties(prefix = "app.jwt")
class JwtProperties {
    var algorithm: String = "SHA256withECDSA"
    var keyType: String? = null
}
