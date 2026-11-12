//! Configuration frontends: `.properties`, YAML and JSON.
//!
//! Both flatten entries the way Spring Boot names them (`a.b[0].c`) and emit
//! one [`FactKind::Property`] per scalar value, located at the value. Nothing
//! is interpreted: profiles, placeholders (`${...}`) and anchors are left
//! as written, and comments produce nothing.

mod json;
mod properties;
#[cfg(test)]
mod tests;
mod yaml;

pub use json::JsonFrontend;
pub use properties::PropertiesFrontend;
pub use yaml::YamlFrontend;
