package com.example.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("app.token")
data class TokenProperties(val signature: String)
