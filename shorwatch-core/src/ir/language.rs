//! Source languages and the platforms rules target.

use serde::{Deserialize, Serialize};

/// Source language of a [`SourceUnit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Language {
    Java,
    Kotlin,
    /// C# sources (`.cs`).
    #[serde(rename = "csharp")]
    CSharp,
    /// `.properties` files (Spring Boot, Quarkus, Micronaut...).
    Properties,
    /// YAML configuration files.
    Yaml,
    /// Keys and certificates: PEM and DER files, Java keystores, PKCS#12
    /// and SSH keys.
    #[serde(rename = "key-material")]
    KeyMaterial,
    /// A Maven `pom.xml`.
    Maven,
    /// A Gradle build script, in Groovy (`build.gradle`) or Kotlin
    /// (`build.gradle.kts`).
    Gradle,
    /// A Gradle version catalog (`libs.versions.toml`).
    #[serde(rename = "version-catalog")]
    VersionCatalog,
}

impl Language {
    /// How reports name the language.
    pub fn label(self) -> &'static str {
        match self {
            Language::Java => "Java",
            Language::Kotlin => "Kotlin",
            Language::CSharp => "C#",
            Language::Properties => ".properties",
            Language::Yaml => "YAML",
            Language::KeyMaterial => "key material",
            Language::Maven => "Maven",
            Language::Gradle => "Gradle",
            Language::VersionCatalog => "version catalog",
        }
    }

    pub fn platform(self) -> Platform {
        match self {
            Language::Java | Language::Kotlin => Platform::Jvm,
            Language::CSharp => Platform::Dotnet,
            Language::Properties | Language::Yaml => Platform::Config,
            Language::KeyMaterial => Platform::Keys,
            Language::Maven | Language::Gradle | Language::VersionCatalog => Platform::Build,
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
    /// .NET: the base class library and its packages. Rules describe APIs
    /// that C# (and, later, F# and Visual Basic) call the same way.
    Dotnet,
    Config,
    /// Key material: the algorithm of keys and certificates themselves,
    /// whatever file holds them.
    Keys,
    /// Build files: the libraries a project depends on. They are inventoried
    /// (see [`crate::inventory`]), not matched by rules.
    Build,
}
