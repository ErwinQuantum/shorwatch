//! Source languages and the platforms rules target.

use serde::{Deserialize, Serialize};

/// Source language of a [`SourceUnit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Language {
    Java,
    Kotlin,
    /// `.properties` files (Spring Boot, Quarkus, Micronaut...).
    Properties,
    /// YAML configuration files.
    Yaml,
    /// Keys and certificates: PEM and DER files, Java keystores, PKCS#12
    /// and SSH keys.
    #[serde(rename = "key-material")]
    KeyMaterial,
}

impl Language {
    pub fn platform(self) -> Platform {
        match self {
            Language::Java | Language::Kotlin => Platform::Jvm,
            Language::Properties | Language::Yaml => Platform::Config,
            Language::KeyMaterial => Platform::Keys,
        }
    }
}

/// What a rule targets. Several languages share a platform: JVM rules describe
/// library APIs (JCA, Nimbus, Spring...) that Java and Kotlin call the same
/// way; config rules describe keys whatever the file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Platform {
    Jvm,
    Config,
    /// Key material: the algorithm of keys and certificates themselves,
    /// whatever file holds them.
    Keys,
}
