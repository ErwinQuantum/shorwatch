//! References to types, as precisely as the frontend could resolve them.

use serde::Serialize;

/// A reference to a type as the frontend could resolve it.
///
/// `qualified` is only set when the frontend is certain (explicit import or a
/// fully qualified name in the source); otherwise matching falls back to the
/// simple name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct TypeRef {
    pub name: String,
    pub qualified: Option<String>,
}

impl TypeRef {
    pub fn simple(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            qualified: None,
        }
    }

    pub fn qualified(qualified: impl Into<String>) -> Self {
        let qualified = qualified.into();
        let name = simple_name(&qualified).to_owned();
        Self {
            name,
            qualified: Some(qualified),
        }
    }

    /// Whether this reference denotes `wanted`, a fully qualified type name.
    pub fn is(&self, wanted: &str) -> bool {
        match &self.qualified {
            Some(qualified) => qualified == wanted,
            None => self.name == simple_name(wanted),
        }
    }

    /// The most precise name available, used for marker matching.
    pub fn best_name(&self) -> &str {
        self.qualified.as_deref().unwrap_or(&self.name)
    }
}

fn simple_name(qualified: &str) -> &str {
    qualified.rsplit('.').next().unwrap_or(qualified)
}
