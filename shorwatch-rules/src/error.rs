//! Why loading rules failed.

use std::path::PathBuf;

use shorwatch_core::{LibraryError, RuleError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("{origin}: {message}")]
    Parse { origin: String, message: String },
    #[error("{origin}: unknown profile `{profile}`")]
    UnknownProfile { origin: String, profile: String },
    #[error("{origin}: unknown marker set `{markers}`")]
    UnknownMarkers { origin: String, markers: String },
    #[error("{origin}: `{name}` is already defined by {previous}")]
    Duplicate {
        origin: String,
        name: String,
        previous: String,
    },
    #[error("failed to read `{}`: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Invalid(#[from] RuleError),
    #[error(transparent)]
    InvalidLibrary(#[from] LibraryError),
}
