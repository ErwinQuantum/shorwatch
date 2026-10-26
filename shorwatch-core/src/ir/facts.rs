//! Facts: what the code (or config) does that rules can match.

use serde::Serialize;

use super::{Location, ScopeId, TypeRef};

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
