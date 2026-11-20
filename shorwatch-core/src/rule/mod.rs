//! Rule model.
//!
//! [`Rule`] is the fully resolved, declarative shape of a rule (assembled from
//! YAML files by `shorwatch-rules`, or built in code). [`RuleSet::compile`] turns
//! rules into their executable form and enforces the domain invariants, most
//! importantly that a rule for an algorithm broken by Shor can never carry an
//! automatic fix.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ir::{Platform, ScopeKind};

mod compile;
mod crypto;
mod error;
mod note;
mod shape;
#[cfg(test)]
pub(crate) mod tests;
mod usage;

pub use compile::RuleSet;
pub(crate) use compile::{CompiledArg, CompiledMarker, CompiledPattern, CompiledRule};
pub use crypto::{CryptoFunction, CryptoProperties, Primitive};
pub use error::RuleError;
pub use note::{Note, NoteSet, Observation, ObservationKind};
pub use shape::AgreementShape;
pub use usage::Usage;

/// Which quantum attack weakens the algorithm. This decides what kind of
/// remediation is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Broken outright by Shor's algorithm (RSA, DH, ECC…). Migrating means
    /// changing the protocol, so remediation is advice only.
    Shor,
    /// Security margin halved by Grover's algorithm (AES-128, SHA-1, 3DES…).
    /// Usually fixed by a parameter change, so a mechanical fix is allowed.
    Grover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, e.g. `jvm.jca.rsa`. Used as the SARIF rule id.
    pub id: String,
    pub platform: Platform,
    /// Human name of the detected algorithm, e.g. `RSA`.
    pub algorithm: String,
    pub category: Category,
    pub severity: Severity,
    /// One-line summary of the problem.
    pub title: String,
    /// What was found and why it matters.
    pub message: String,
    /// Migration advice. Always educational text, never an edit.
    pub suggestion: String,
    pub references: Vec<Reference>,
    pub patterns: Vec<Pattern>,
    #[serde(default)]
    pub hybrid: Option<HybridSpec>,
    /// Mechanical fix. Only accepted for [`Category::Grover`] rules.
    #[serde(default)]
    pub fix: Option<FixSpec>,
    /// What kind of cryptography this is, for inventories (CBOM).
    #[serde(default)]
    pub crypto: Option<CryptoProperties>,
    /// How the algorithm is used where the rule matches, unless a pattern
    /// says otherwise: a profile whose algorithm has a single use declares it
    /// once. A Shor-category pattern with neither is `unknown`.
    #[serde(default)]
    pub usage: Option<Usage>,
    /// Advice for a finding with that usage, instead of `suggestion`: RSA
    /// that signs and RSA that wraps a key have different successors. A
    /// usage with no entry gets `suggestion`. Shor-category rules only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub suggestions: BTreeMap<Usage, String>,
    /// The shape of the key agreement where the rule matches, unless a
    /// pattern says otherwise: a profile whose every pattern is one shape
    /// (JOSE `ECDH-ES`) declares it once. A key-agreement pattern with
    /// neither is `undetermined`.
    #[serde(default)]
    pub shape: Option<AgreementShape>,
    /// Advice for a finding of that shape, before `suggestions` and
    /// `suggestion`: ephemeral-static agreement is already KEM-shaped, while
    /// static-static has no one-to-one replacement. Shor-category rules only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shape_suggestions: BTreeMap<AgreementShape, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Pattern {
    /// `Type.method(...)` or `receiver.method(...)` where the receiver has `type`.
    Call {
        #[serde(rename = "type")]
        receiver: String,
        method: String,
        #[serde(default)]
        arg: Option<ArgPattern>,
        /// A second argument that must match as well: `System.setProperty`
        /// names the setting in one argument and its value in the other.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        with_arg: Option<ArgPattern>,
        /// Constrains the factory call that created the receiver
        /// (`KeyGenerator.getInstance("AES")`). A receiver of unknown origin
        /// still matches: the rule errs on the side of reporting.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<ArgPattern>,
        /// Skips the call when a method matching this regex is called on its
        /// result later in the chain. Lets a rule report a library *default*
        /// (`withJwkSetUri(u).build()` verifies with RS256) only when nothing
        /// in the chain chooses another (`.jwsAlgorithm(ES256)`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unless_chain: Option<String>,
        /// How this match uses the algorithm; the rule's `usage` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<Usage>,
        /// The shape of the key agreement it finds, where the code or the name
        /// says so (key-agreement usage only); the rule's `shape` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shape: Option<AgreementShape>,
    },
    /// `new Type(...)`.
    Construct {
        #[serde(rename = "type")]
        ty: String,
        #[serde(default)]
        arg: Option<ArgPattern>,
        /// How this match uses the algorithm; the rule's `usage` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<Usage>,
        /// The shape of the key agreement it finds, where the code or the name
        /// says so (key-agreement usage only); the rule's `shape` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shape: Option<AgreementShape>,
    },
    /// `Type.FIELD`: a static field or enum constant of `type` whose name
    /// matches the `matches` regex (any field when absent).
    Field {
        #[serde(rename = "type")]
        owner: String,
        #[serde(default)]
        matches: Option<String>,
        /// Skips the read when it is an argument of a method whose name
        /// matches this regex (`HashAlgorithmName.SHA1` given to PBKDF2).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unless_call: Option<String>,
        /// How this match uses the algorithm; the rule's `usage` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<Usage>,
        /// The shape of the key agreement it finds, where the code or the name
        /// says so (key-agreement usage only); the rule's `shape` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shape: Option<AgreementShape>,
    },
    /// A string literal anywhere in the code whose value matches `matches`.
    /// Only for names specific enough to stand alone (`TLS_ECDHE_RSA_...`):
    /// they reach their API through arrays, lists or constants that argument
    /// patterns cannot see. `unless_call` skips literals passed to a method
    /// whose name matches it, such as `setExcludeCipherSuites`.
    Literal {
        matches: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unless_call: Option<String>,
        /// Reports the literal only when it is an argument of a method whose
        /// name matches this regex (`setNamedGroups`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        in_call: Option<String>,
        /// How this match uses the algorithm; the rule's `usage` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<Usage>,
        /// The shape of the key agreement it finds, where the code or the name
        /// says so (key-agreement usage only); the rule's `shape` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shape: Option<AgreementShape>,
    },
    /// A configuration entry whose key matches the `key` regex and whose value
    /// matches `matches` (any value when absent).
    Property {
        key: String,
        #[serde(default)]
        matches: Option<String>,
        /// Skips the entry when another entry of the same file has a key
        /// matching this regex: `jwk-set-uri` verifies with RS256 only while
        /// no `jws-algorithms` says otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unless_property: Option<String>,
        /// How this match uses the algorithm; the rule's `usage` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<Usage>,
        /// The shape of the key agreement it finds, where the code or the name
        /// says so (key-agreement usage only); the rule's `shape` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shape: Option<AgreementShape>,
    },
    /// A key or certificate whose public key `algorithm` and, for
    /// certificates, `signature` algorithm match (either absent: any).
    Key {
        #[serde(default)]
        algorithm: Option<String>,
        #[serde(default)]
        signature: Option<String>,
        /// How this match uses the algorithm; the rule's `usage` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<Usage>,
        /// The shape of the key agreement it finds, where the code or the name
        /// says so (key-agreement usage only); the rule's `shape` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shape: Option<AgreementShape>,
    },
}

impl Pattern {
    /// The usage this pattern states, if it states one.
    pub fn usage(&self) -> Option<Usage> {
        match self {
            Pattern::Call { usage, .. }
            | Pattern::Construct { usage, .. }
            | Pattern::Field { usage, .. }
            | Pattern::Literal { usage, .. }
            | Pattern::Property { usage, .. }
            | Pattern::Key { usage, .. } => *usage,
        }
    }

    /// The shape this pattern states, if it states one.
    pub fn shape(&self) -> Option<AgreementShape> {
        match self {
            Pattern::Call { shape, .. }
            | Pattern::Construct { shape, .. }
            | Pattern::Field { shape, .. }
            | Pattern::Literal { shape, .. }
            | Pattern::Property { shape, .. }
            | Pattern::Key { shape, .. } => *shape,
        }
    }

    fn arg(&self) -> Option<&ArgPattern> {
        match self {
            Pattern::Call { arg, .. } | Pattern::Construct { arg, .. } => arg.as_ref(),
            Pattern::Field { .. }
            | Pattern::Literal { .. }
            | Pattern::Property { .. }
            | Pattern::Key { .. } => None,
        }
    }
}

/// Constrains one argument. `matches` is a regex tested against the
/// argument's literal value (integers are matched by their decimal text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgPattern {
    #[serde(default)]
    pub index: usize,
    pub matches: String,
}

/// How to recognise that a finding already lives next to post-quantum code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridSpec {
    /// How far around the finding to look for markers. Imports always count
    /// for the whole file.
    #[serde(default = "HybridSpec::default_scope")]
    pub scope: ScopeKind,
    pub markers: Vec<Marker>,
}

impl HybridSpec {
    fn default_scope() -> ScopeKind {
        ScopeKind::Type
    }
}

/// A regex matched against one kind of fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Marker {
    Import(String),
    Literal(String),
    Type(String),
}

/// Rewrite of the argument matched by the pattern: `replace` is a regex over
/// the argument's source text, `with` its replacement (`$1` etc. allowed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixSpec {
    pub description: String,
    pub replace: String,
    pub with: String,
}
