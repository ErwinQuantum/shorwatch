//! Source languages and the platforms rules target.

use serde::{Deserialize, Serialize};

/// Source language of a [`SourceUnit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Language {
    Java,
    /// `.properties` files (Spring Boot, Quarkus, Micronaut...).
    Properties,
    /// YAML configuration files.
    Yaml,
}

impl Language {
    pub fn platform(self) -> Platform {
        match self {
            Language::Java => Platform::Jvm,
            Language::Properties | Language::Yaml => Platform::Config,
        }
    }
}

/// What a rule targets. Several languages share a platform: JVM rules describe
/// library APIs (JCA, Nimbus, Spring...) that Java and, later, Kotlin call the
/// same way; config rules describe keys whatever the file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Platform {
    Jvm,
    Config,
}
