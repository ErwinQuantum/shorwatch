package com.example.config

import org.springframework.boot.context.properties.ConfigurationProperties

/** No `app.legacy.*` key is set: the default is what runs. */
@ConfigurationProperties("app.legacy")
class LegacyProperties {
    var digest: String = "SHA-1"
}
