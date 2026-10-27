//! Why a rule was rejected.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("rule `{0}`: duplicate rule id")]
    DuplicateId(String),
    #[error("rule `{id}`: `{field}` must not be empty")]
    Empty { id: String, field: &'static str },
    #[error("rule `{id}`: invalid regex `{pattern}`: {reason}")]
    InvalidRegex {
        id: String,
        pattern: String,
        reason: String,
    },
    #[error(
        "rule `{0}`: Shor-category rules cannot declare a `fix`; migrating away from \
         RSA/ECC changes the protocol and must stay a human decision"
    )]
    FixNotAllowed(String),
    #[error("rule `{0}`: a `fix` needs at least one pattern with an `arg` to rewrite")]
    FixWithoutArg(String),
    #[error("rule `{0}`: reference `{1}` must be an http(s) URL (reports link to it)")]
    ReferenceNotHttp(String, String),
}
