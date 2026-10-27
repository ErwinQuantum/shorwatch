use serde::Serialize;

use crate::ir::{CodeRole, FlowStep, Location};
use crate::rule::{Category, CryptoProperties, Reference, Severity};

/// Whether the project still depends solely on the vulnerable algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Vulnerable,
    /// The classical algorithm sits next to post-quantum code, typically a
    /// hybrid scheme mid-migration.
    InTransition,
}

/// The post-quantum marker that turned a finding into [`Status::InTransition`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HybridEvidence {
    pub text: String,
    pub location: Location,
}

/// A concrete edit for a Grover-category finding: replace the source text at
/// `location` with `replacement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuggestedFix {
    pub description: String,
    pub location: Location,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub algorithm: String,
    pub category: Category,
    pub severity: Severity,
    pub status: Status,
    pub title: String,
    pub message: String,
    pub suggestion: String,
    pub references: Vec<Reference>,
    pub path: String,
    /// Whether the finding is in production or test code.
    pub role: CodeRole,
    pub location: Location,
    /// What was found, when the source line does not show it: a
    /// certificate's subject, key size and expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How the matched value reached `location` when it was written
    /// elsewhere: the literal first, then each assignment, call or return.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flow: Vec<FlowStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid_evidence: Option<HybridEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<SuggestedFix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoProperties>,
}
