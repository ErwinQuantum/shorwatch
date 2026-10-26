use serde::Serialize;

use crate::ir::Location;
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
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid_evidence: Option<HybridEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<SuggestedFix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoProperties>,
}
