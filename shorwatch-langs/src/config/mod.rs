//! Configuration frontends: `.properties` and YAML.
//!
//! Both flatten entries the way Spring Boot names them (`a.b[0].c`) and emit
//! one [`FactKind::Property`] per scalar value, located at the value. Nothing
//! is interpreted: profiles, placeholders (`${...}`) and anchors are left
//! as written, and comments produce nothing.

use shorwatch_core::ir::{Location, Position};

mod properties;
#[cfg(test)]
mod tests;
mod yaml;

pub use properties::PropertiesFrontend;
pub use yaml::YamlFrontend;

/// Location of `start..end`, with columns in code points like the Java frontend.
fn location(src: &str, start: usize, end: usize) -> Location {
    Location {
        start: position(src, start),
        end: position(src, end),
        start_byte: start,
        end_byte: end,
    }
}

fn position(src: &str, byte: usize) -> Position {
    let before = &src[..byte];
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    Position {
        line: u32::try_from(before.matches('\n').count() + 1).unwrap_or(u32::MAX),
        column: u32::try_from(src[line_start..byte].chars().count() + 1).unwrap_or(u32::MAX),
    }
}
