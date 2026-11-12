//! The catalog of known cryptographic libraries: data in, compiled regexes
//! out. Like rules, it lives in YAML files (`shorwatch-rules`), so knowing a
//! new library never touches the code.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::version;
use crate::rule::Reference;

/// What a library is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// A general-purpose cryptography provider or API.
    Provider,
    /// JSON Web Tokens and JOSE.
    Jwt,
    /// SSH clients and servers.
    Ssh,
    /// XML signature and encryption (SAML, WS-Security).
    XmlSignature,
    /// A cloud key management service client.
    Kms,
    /// Post-quantum cryptography.
    PostQuantum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibrarySpec {
    /// Stable identifier (`bouncycastle`).
    pub id: String,
    /// How reports name it (`BouncyCastle`).
    pub name: String,
    pub role: Role,
    /// Maven coordinates that identify it: a dependency matches when its
    /// group and its artifact match one entry's regexes.
    #[serde(default)]
    pub matches: Vec<Coordinates>,
    /// NuGet package ids that identify it (regexes; ids ignore case).
    #[serde(default)]
    pub nuget: Vec<String>,
    /// From which version the library offers post-quantum algorithms, when it
    /// does. Absent: nothing is claimed either way.
    #[serde(default)]
    pub post_quantum: Option<PostQuantumSpec>,
    /// One line on what the library does for a project, for people.
    pub summary: String,
    #[serde(default)]
    pub references: Vec<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinates {
    pub group: String,
    pub artifact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostQuantumSpec {
    /// The first release with the algorithms below (`1.79`).
    pub since: String,
    pub algorithms: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LibraryError {
    #[error("library `{0}`: duplicate library id")]
    DuplicateId(String),
    #[error("library `{id}`: `{field}` must not be empty")]
    Empty { id: String, field: &'static str },
    #[error("library `{id}`: invalid regex `{pattern}`: {reason}")]
    InvalidRegex {
        id: String,
        pattern: String,
        reason: String,
    },
    #[error("library `{id}`: `{since}` is not a version number")]
    InvalidVersion { id: String, since: String },
    #[error("library `{0}`: reference `{1}` must be an http(s) URL (reports link to it)")]
    ReferenceNotHttp(String, String),
}

/// The known libraries, compiled.
#[derive(Debug, Clone, Default)]
pub struct LibraryCatalog {
    libraries: Vec<Compiled>,
}

#[derive(Debug, Clone)]
struct Compiled {
    spec: LibrarySpec,
    matches: Vec<(Regex, Regex)>,
    nuget: Vec<Regex>,
}

impl LibraryCatalog {
    /// Validates the specs and compiles their regexes.
    pub fn compile(specs: Vec<LibrarySpec>) -> Result<Self, LibraryError> {
        let mut libraries: Vec<Compiled> = Vec::with_capacity(specs.len());
        for spec in specs {
            let id = spec.id.clone();
            if libraries.iter().any(|l| l.spec.id == id) {
                return Err(LibraryError::DuplicateId(id));
            }
            let empty = |field| LibraryError::Empty {
                id: id.clone(),
                field,
            };
            if spec.name.trim().is_empty() {
                return Err(empty("name"));
            }
            if spec.summary.trim().is_empty() {
                return Err(empty("summary"));
            }
            if spec.matches.is_empty() && spec.nuget.is_empty() {
                return Err(empty("matches"));
            }
            if let Some(pq) = &spec.post_quantum {
                if version::parse(&pq.since).is_none() {
                    return Err(LibraryError::InvalidVersion {
                        id,
                        since: pq.since.clone(),
                    });
                }
                if pq.algorithms.is_empty() {
                    return Err(empty("post_quantum.algorithms"));
                }
            }
            for reference in &spec.references {
                let url = reference.url.to_ascii_lowercase();
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(LibraryError::ReferenceNotHttp(id, reference.url.clone()));
                }
            }
            let regex = |pattern: &str| {
                Regex::new(pattern).map_err(|e| LibraryError::InvalidRegex {
                    id: id.clone(),
                    pattern: pattern.to_owned(),
                    reason: e.to_string(),
                })
            };
            let matches = spec
                .matches
                .iter()
                .map(|c| Ok((regex(&c.group)?, regex(&c.artifact)?)))
                .collect::<Result<_, LibraryError>>()?;
            // NuGet ids are case-insensitive: `newtonsoft.json` is `Newtonsoft.Json`.
            let nuget = spec
                .nuget
                .iter()
                .map(|pattern| {
                    RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| LibraryError::InvalidRegex {
                            id: id.clone(),
                            pattern: pattern.clone(),
                            reason: e.to_string(),
                        })
                })
                .collect::<Result<_, LibraryError>>()?;
            libraries.push(Compiled {
                spec,
                matches,
                nuget,
            });
        }
        Ok(Self { libraries })
    }

    /// The library `group:artifact` is, if known.
    pub fn find(&self, group: &str, artifact: &str) -> Option<&LibrarySpec> {
        self.libraries
            .iter()
            .find(|l| {
                l.matches
                    .iter()
                    .any(|(g, a)| g.is_match(group) && a.is_match(artifact))
            })
            .map(|l| &l.spec)
    }

    /// The library the NuGet package `id` is, if known.
    pub fn find_package(&self, id: &str) -> Option<&LibrarySpec> {
        self.libraries
            .iter()
            .find(|l| l.nuget.iter().any(|p| p.is_match(id)))
            .map(|l| &l.spec)
    }

    pub fn len(&self) -> usize {
        self.libraries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.libraries.is_empty()
    }
}
