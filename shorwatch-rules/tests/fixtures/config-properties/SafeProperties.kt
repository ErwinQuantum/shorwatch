package com.example.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "app.safe")
class SafeProperties {
    var digest: String? = null
}
