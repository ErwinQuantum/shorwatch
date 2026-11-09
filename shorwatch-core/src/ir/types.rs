//! References to types, as precisely as the frontend could resolve them.

use serde::Serialize;

/// A reference to a type as the frontend could resolve it.
///
/// `qualified` is only set when the frontend is certain (explicit import or a
/// fully qualified name in the source); otherwise matching falls back to
/// `name`, the type as written without its package: `Cipher`, or `Outer.Inner`
/// for a nested type whose outer type was not imported.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct TypeRef {
    pub name: String,
    pub qualified: Option<String>,
    /// The packages an unqualified `name` can come from: the file's own
    /// package, its on-demand imports (`import a.b.*`) and the language's
    /// implicit ones (`java.lang`). Empty when unknown, which accepts any.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
}

impl TypeRef {
    pub fn simple(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            qualified: None,
            packages: Vec::new(),
        }
    }

    /// An unqualified name that can only come from one of `packages`.
    pub fn in_packages(name: impl Into<String>, packages: Vec<String>) -> Self {
        Self {
            packages,
            ..Self::simple(name)
        }
    }

    pub fn qualified(qualified: impl Into<String>) -> Self {
        let qualified = qualified.into();
        let name = simple_name(&qualified).to_owned();
        Self {
            name,
            qualified: Some(qualified),
            packages: Vec::new(),
        }
    }

    /// Whether this reference denotes `wanted`, a fully qualified type name.
    /// Without a qualified name the whole type path must agree: a bare
    /// `Builder` or `Context.Builder` is not `com.nimbusds.jose.jwk.ECKey.Builder`.
    /// The type must also live in a package the name can come from: a
    /// same-package `KeyType` is not Azure's.
    pub fn is(&self, wanted: &str) -> bool {
        match &self.qualified {
            Some(qualified) => qualified == wanted,
            // The name can come from any of `packages`: the wanted type is
            // one of them followed by the name (an empty package is the
            // global namespace). Namespaces and types are both capitalised
            // in .NET, so nothing here may tell them apart by their case.
            None if !self.packages.is_empty() => self.packages.iter().any(|package| {
                if package.is_empty() {
                    wanted == self.name
                } else {
                    wanted
                        .strip_prefix(package.as_str())
                        .and_then(|rest| rest.strip_prefix('.'))
                        == Some(self.name.as_str())
                }
            }),
            // Package unknown: only the type path (by the JVM convention) has
            // to agree.
            None => self.name == type_path(wanted),
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

/// `com.nimbusds.jose.jwk.ECKey.Builder` -> `ECKey.Builder`: the name without
/// its package, which by JVM convention is everything from the first segment
/// starting with an upper-case letter.
fn type_path(qualified: &str) -> &str {
    let mut start = 0;
    for segment in qualified.split('.') {
        if segment.chars().next().is_some_and(char::is_uppercase) {
            return &qualified[start..];
        }
        start += segment.len() + 1;
    }
    simple_name(qualified)
}
