//! Build files: the libraries a project declares. They are found by file
//! name (`pom.xml`, `build.gradle`...), not by extension, and become
//! [`FactKind::Dependency`](shorwatch_core::ir::FactKind::Dependency) facts
//! for the dependency inventory.
//!
//! - `maven`: `pom.xml`, read as XML events;
//! - `gradle`: `build.gradle` and `build.gradle.kts`, tokenized;
//! - `catalog`: `libs.versions.toml`;
//! - `nuget`: `*.csproj`, `packages.config`, `Directory.Packages.props`.

mod catalog;
mod gradle;
mod maven;
mod nuget;
#[cfg(test)]
mod tests;

pub use catalog::VersionCatalogFrontend;
pub use gradle::GradleFrontend;
pub use maven::MavenFrontend;
pub use nuget::NuGetFrontend;
