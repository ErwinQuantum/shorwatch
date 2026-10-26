//! Language-neutral intermediate representation of a source file.
//!
//! Frontends (see `shorwatch-langs`) lower a concrete syntax tree into a
//! [`SourceUnit`]: a flat list of [`Fact`]s, each attached to a lexical
//! [`Scope`]. The engine only ever sees this model, so it can be built by hand
//! in tests, by an LSP server from an in-memory buffer, or by a future
//! dependency scanner without involving tree-sitter at all.

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

/// A point in the source. Both fields are 1-based; `column` counts Unicode
/// code points, which is what SARIF's `unicodeCodePoints` column kind expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

/// A source range, as positions for humans and byte offsets for edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Location {
    pub start: Position,
    pub end: Position,
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Location {
    /// Convenience constructor for single-line ranges, mostly useful in tests.
    pub fn line(line: u32, start_column: u32, end_column: u32) -> Self {
        Self {
            start: Position {
                line,
                column: start_column,
            },
            end: Position {
                line,
                column: end_column,
            },
            start_byte: 0,
            end_byte: 0,
        }
    }
}

/// Lexical nesting level. Ordered from widest to narrowest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    File,
    /// A class, interface, enum or record (or the language's equivalent).
    Type,
    /// A method, constructor or initializer block.
    Method,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ScopeId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Scope {
    pub kind: ScopeKind,
    pub name: Option<String>,
    pub parent: Option<ScopeId>,
}

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

/// Statically known value of an argument expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgValue {
    Str(String),
    Int(i64),
    /// A value injected from configuration, e.g. a `@Value("${jwt.alg:RS256}")`
    /// field. `resolved` holds every value the project's config files assign
    /// to `key` (filled by [`crate::link`]); `default` applies when none do.
    Injected {
        key: String,
        default: Option<String>,
        resolved: Vec<String>,
    },
    /// Anything the frontend could not fold to a literal.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Arg {
    pub value: ArgValue,
    /// The argument exactly as written in the source.
    pub raw: String,
    /// The constant (`KEY_BITS`) or property (`${jwt.alg}`) the value was
    /// resolved through, if any. Fixes are never offered for such arguments,
    /// since editing the use site would not be a faithful rewrite.
    pub resolved_via: Option<String>,
    pub location: Location,
}

impl Arg {
    pub fn str(value: impl Into<String>, location: Location) -> Self {
        let value = value.into();
        Self {
            raw: format!("{value:?}"),
            value: ArgValue::Str(value),
            resolved_via: None,
            location,
        }
    }

    pub fn int(value: i64, location: Location) -> Self {
        Self {
            raw: value.to_string(),
            value: ArgValue::Int(value),
            resolved_via: None,
            location,
        }
    }

    /// Texts that argument patterns are matched against: a pattern matches if
    /// any of them does. Several only for injected values set differently by
    /// different config files (profiles).
    pub fn match_texts(&self) -> Vec<String> {
        match &self.value {
            ArgValue::Str(s) => vec![s.clone()],
            ArgValue::Int(i) => vec![i.to_string()],
            ArgValue::Injected {
                default, resolved, ..
            } if resolved.is_empty() => default.iter().cloned().collect(),
            ArgValue::Injected { resolved, .. } => resolved.clone(),
            ArgValue::Unknown => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    /// A method call. `receiver` is the static type of the call target when known.
    Call {
        receiver: Option<TypeRef>,
        method: String,
        args: Vec<Arg>,
    },
    /// An object instantiation.
    Construct { ty: TypeRef, args: Vec<Arg> },
    /// A read of a static field or enum constant, e.g. `JWSAlgorithm.RS256`.
    /// Crypto libraries often name algorithms this way instead of by string.
    Field { owner: TypeRef, name: String },
    /// An import (or equivalent). Imports apply to the whole file.
    Import { path: String },
    /// A string literal anywhere in the code.
    Literal { value: String },
    /// A configuration entry. `key` is flattened with dots and list indexes as
    /// written (`a.b[0].c`); `value` is the scalar as text.
    Property { key: String, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fact {
    pub kind: FactKind,
    pub scope: ScopeId,
    pub location: Location,
}

/// One analyzed file. `path` is an opaque identifier (a relative path, a URI…);
/// the core never touches the file system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceUnit {
    path: String,
    language: Language,
    scopes: Vec<Scope>,
    pub(crate) facts: Vec<Fact>,
}

impl SourceUnit {
    pub fn new(path: impl Into<String>, language: Language) -> Self {
        Self {
            path: path.into(),
            language,
            scopes: vec![Scope {
                kind: ScopeKind::File,
                name: None,
                parent: None,
            }],
            facts: Vec::new(),
        }
    }

    pub const ROOT: ScopeId = ScopeId(0);

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn language(&self) -> Language {
        self.language
    }

    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// # Panics
    /// If `id` does not belong to this unit.
    pub fn scope(&self, id: ScopeId) -> &Scope {
        &self.scopes[id.0 as usize]
    }

    /// # Panics
    /// If `parent` does not belong to this unit.
    pub fn add_scope(&mut self, kind: ScopeKind, name: Option<String>, parent: ScopeId) -> ScopeId {
        assert!(
            (parent.0 as usize) < self.scopes.len(),
            "unknown parent scope"
        );
        let id = ScopeId(u32::try_from(self.scopes.len()).expect("too many scopes"));
        self.scopes.push(Scope {
            kind,
            name,
            parent: Some(parent),
        });
        id
    }

    pub fn push(&mut self, kind: FactKind, scope: ScopeId, location: Location) {
        self.facts.push(Fact {
            kind,
            scope,
            location,
        });
    }

    /// Walks up from `id` to the nearest scope of `kind` or wider. Falls back
    /// to the file scope.
    pub fn enclosing(&self, id: ScopeId, kind: ScopeKind) -> ScopeId {
        let mut current = id;
        loop {
            let scope = self.scope(current);
            if scope.kind <= kind {
                return current;
            }
            match scope.parent {
                Some(parent) => current = parent,
                None => return current,
            }
        }
    }

    /// Whether `inner` is `outer` or nested inside it.
    pub fn is_within(&self, inner: ScopeId, outer: ScopeId) -> bool {
        let mut current = Some(inner);
        while let Some(id) = current {
            if id == outer {
                return true;
            }
            current = self.scope(id).parent;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_ref_matches_by_qualified_name_when_known() {
        assert!(TypeRef::qualified("javax.crypto.Cipher").is("javax.crypto.Cipher"));
        assert!(!TypeRef::qualified("com.acme.Cipher").is("javax.crypto.Cipher"));
    }

    #[test]
    fn type_ref_falls_back_to_simple_name() {
        assert!(TypeRef::simple("Cipher").is("javax.crypto.Cipher"));
        assert!(!TypeRef::simple("Signature").is("javax.crypto.Cipher"));
    }

    #[test]
    fn enclosing_walks_up_to_requested_kind() {
        let mut unit = SourceUnit::new("A.java", Language::Java);
        let class = unit.add_scope(ScopeKind::Type, Some("A".into()), SourceUnit::ROOT);
        let method = unit.add_scope(ScopeKind::Method, Some("run".into()), class);

        assert_eq!(unit.enclosing(method, ScopeKind::Type), class);
        assert_eq!(unit.enclosing(method, ScopeKind::Method), method);
        assert_eq!(unit.enclosing(method, ScopeKind::File), SourceUnit::ROOT);
        assert_eq!(
            unit.enclosing(SourceUnit::ROOT, ScopeKind::Type),
            SourceUnit::ROOT
        );
    }

    #[test]
    fn is_within_follows_parents() {
        let mut unit = SourceUnit::new("A.java", Language::Java);
        let a = unit.add_scope(ScopeKind::Type, Some("A".into()), SourceUnit::ROOT);
        let b = unit.add_scope(ScopeKind::Type, Some("B".into()), SourceUnit::ROOT);
        let m = unit.add_scope(ScopeKind::Method, None, a);

        assert!(unit.is_within(m, a));
        assert!(unit.is_within(m, SourceUnit::ROOT));
        assert!(!unit.is_within(m, b));
    }
}
