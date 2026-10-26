//! Language-neutral intermediate representation of a source file.
//!
//! Frontends (see `shorwatch-langs`) lower a concrete syntax tree into a
//! [`SourceUnit`]: a flat list of [`Fact`]s, each attached to a lexical
//! [`Scope`]. The engine only ever sees this model, so it can be built by hand
//! in tests, by an LSP server from an in-memory buffer, or by a future
//! dependency scanner without involving tree-sitter at all.

mod facts;
mod language;
mod location;
#[cfg(test)]
mod tests;
mod types;
mod unit;

pub use facts::{Arg, ArgValue, Candidate, Fact, FactKind, FlowStep, MethodSummary};
pub use language::{Language, Platform};
pub use location::{Location, Position};
pub use types::TypeRef;
pub use unit::{CodeRole, Scope, ScopeId, ScopeKind, SourceUnit};
