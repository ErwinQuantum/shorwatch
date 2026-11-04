//! Facts: what the code (or config) does that rules can match.

use serde::Serialize;

use super::{Location, ScopeId, TypeRef};

/// Statically known value of an argument expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// The values a variable, parameter or method result may hold, each with
    /// the path it takes to the argument (data flow).
    OneOf(Vec<Candidate>),
    /// Among [`ArgValue::OneOf`] candidates: parameter `index` (named
    /// `param`) of method `method` of type `owner`, declared in this file.
    /// Its values come from calls in other files, which [`crate::link`]
    /// looks up.
    Param {
        owner: String,
        method: String,
        arity: usize,
        index: usize,
        param: String,
    },
    /// Among [`ArgValue::OneOf`] candidates: the constant `owner.name` of
    /// another file (`KeyType.RSA`), which [`crate::link`] looks up.
    Constant {
        owner: TypeRef,
        name: String,
    },
    /// Among [`ArgValue::OneOf`] candidates: what `owner.method(args)`, a
    /// method of another file, returns. [`crate::link`] looks it up.
    Returns {
        owner: TypeRef,
        method: String,
        args: Vec<Arg>,
    },
    /// Anything the frontend could not fold to a literal.
    Unknown,
}

impl ArgValue {
    /// Texts that argument patterns are matched against: a pattern matches if
    /// any of them does. Several for injected values set differently by
    /// different config files (profiles), and for data-flow candidates.
    pub fn texts(&self) -> Vec<String> {
        match self {
            ArgValue::Str(s) => vec![s.clone()],
            ArgValue::Int(i) => vec![i.to_string()],
            ArgValue::Injected {
                default, resolved, ..
            } if resolved.is_empty() => default.iter().cloned().collect(),
            ArgValue::Injected { resolved, .. } => resolved.clone(),
            ArgValue::OneOf(candidates) => {
                candidates.iter().flat_map(|c| c.value.texts()).collect()
            }
            // Unresolved until `link`; nothing to match on its own.
            ArgValue::Param { .. }
            | ArgValue::Returns { .. }
            | ArgValue::Constant { .. }
            | ArgValue::Unknown => Vec::new(),
        }
    }
}

/// A value an argument may take, and the path it takes to get there: where
/// it is written, then each assignment, call or return it goes through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub value: ArgValue,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flow: Vec<FlowStep>,
}

/// One step of a value's path, such as `assigned to alg` or
/// `passed as alg to sign(...)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowStep {
    /// The file of the step, when it is not the file of the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub location: Location,
    pub note: String,
}

/// What a method of a file returns, for other files' calls to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MethodSummary {
    /// The declaring type, fully qualified (`com.acme.CryptoUtil`).
    pub owner: String,
    pub name: String,
    pub arity: usize,
    /// The declared return type, when it is a type of its own (not a
    /// primitive or `String`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<TypeRef>,
    /// The values of its `return`s, like an argument's candidates.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub returns: Vec<Candidate>,
}

/// A call by its target: `owner.method(...)` with `arity` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallRef {
    pub owner: CallOwner,
    pub method: String,
    pub arity: usize,
}

/// What a [`CallRef`] is called on: a known type, or the result of another
/// call (`a.b().c()`), typed from that call's declared return type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallOwner {
    Type(TypeRef),
    Call(Box<CallRef>),
}

/// A constant a type declares (`static final`, `const val`), for other
/// files that refer to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConstantDecl {
    /// The declaring type, fully qualified.
    pub owner: String,
    pub name: String,
    pub value: ArgValue,
}

/// A type declared in a file and the types it extends or implements, for
/// calls through a supertype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeDecl {
    /// Fully qualified (`com.acme.crypto.FipsProvider`).
    pub name: String,
    pub supertypes: Vec<TypeRef>,
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

    /// See [`ArgValue::texts`].
    pub fn match_texts(&self) -> Vec<String> {
        self.value.texts()
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
        /// Arguments of the factory call that created the receiver, when the
        /// receiver is a variable initialized by one: `["AES"]` for
        /// `g.init(128)` after `g = KeyGenerator.getInstance("AES")`. Lets a
        /// rule tell an AES key generator from an HMAC one. `None` when unknown.
        #[serde(skip_serializing_if = "Option::is_none")]
        receiver_origin: Option<Vec<Arg>>,
        /// When the receiver is itself a call (`Crypto.provider().m()`), that
        /// call: [`crate::link`] types the receiver from the method's
        /// declared return type, wherever the method is declared.
        #[serde(skip_serializing_if = "Option::is_none")]
        receiver_call: Option<CallRef>,
    },
    /// An object instantiation.
    Construct { ty: TypeRef, args: Vec<Arg> },
    /// A read of a static field or enum constant, e.g. `JWSAlgorithm.RS256`.
    /// Crypto libraries often name algorithms this way instead of by string.
    Field { owner: TypeRef, name: String },
    /// An import (or equivalent). Imports apply to the whole file.
    Import { path: String },
    /// A string literal anywhere in the code.
    Literal {
        value: String,
        /// The methods of the calls the literal is an argument of, innermost
        /// first and within one expression: `["of", "setExcludeCipherSuites"]`
        /// for `setExcludeCipherSuites(List.of("..."))`.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        calls: Vec<String>,
    },
    /// A configuration entry. `key` is flattened with dots and list indexes as
    /// written (`a.b[0].c`); `value` is the scalar as text.
    Property { key: String, value: String },
    /// A key or certificate: in a PEM or DER file, a keystore entry, an SSH
    /// key.
    Key {
        /// The public key algorithm: `RSA`, `EC`, `DSA`, `Ed25519`, `X25519`,
        /// `ML-DSA-65`... (the OID in dotted form when unknown).
        algorithm: String,
        /// Key size in bits, when the algorithm has one (RSA, DSA).
        #[serde(skip_serializing_if = "Option::is_none")]
        bits: Option<u32>,
        /// Named curve of an EC key (`secp256r1`).
        #[serde(skip_serializing_if = "Option::is_none")]
        curve: Option<String>,
        /// How a certificate is signed (`SHA256withRSA`), by its issuer.
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        /// What holds the key, for people: `certificate CN=api.example.com
        /// (alias "server"), valid until 2027-03-01`.
        label: String,
    },
    /// A library a build file declares, as Maven coordinates.
    Dependency {
        group: String,
        artifact: String,
        /// The version as far as the file says it: a literal, or a
        /// `${property}` / variable the file defines. `None` when it is
        /// managed elsewhere (a parent POM, a BOM) or cannot be read.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        /// Maven `<scope>` or the Gradle configuration (`implementation`,
        /// `testImplementation`...).
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fact {
    pub kind: FactKind,
    pub scope: ScopeId,
    pub location: Location,
}
