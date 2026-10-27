//! Configuration frontends: `.properties` and YAML.
//!
//! Both flatten entries the way Spring Boot names them (`a.b[0].c`) and emit
//! one [`FactKind::Property`] per scalar value, located at the value. Nothing
//! is interpreted: profiles, placeholders (`${...}`) and anchors are left
//! as written, and comments produce nothing.

mod properties;
#[cfg(test)]
mod tests;
mod yaml;

pub use properties::PropertiesFrontend;
pub use yaml::YamlFrontend;
