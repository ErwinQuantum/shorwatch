package com.example.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app.token")
public record TokenProperties(String signature) {}
