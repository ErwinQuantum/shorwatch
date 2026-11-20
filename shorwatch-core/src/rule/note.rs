//! Notes: what a scan cannot decide, said once per scan.
//!
//! A static scan reads files. Some of what matters is decided elsewhere: the
//! key-exchange groups a TLS connection negotiates come from the JVM or the
//! runtime and from the other peer, not from the code. A repository with no
//! explicit setting would read as clean, so a note says that the topic is in
//! play and that the scan does not read the outcome. A note is data, like a
//! rule, and it is never a finding: it feeds no gate, baseline or SARIF result.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::compile::{CompiledPattern, compile_patterns};
use super::{Pattern, RuleError};
use crate::ir::{Location, Platform};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    /// Stable identifier, e.g. `tls-key-exchange`.
    pub id: String,
    /// The platforms whose units the note looks at.
    pub platforms: Vec<Platform>,
    /// Short name of what the runtime decides, e.g. `TLS`.
    pub topic: String,
    /// What the runtime decides, and that the scan does not analyze it.
    pub text: String,
    /// Code or configuration that shows the topic is in play (an
    /// `SSLContext`, `server.ssl.enabled`).
    #[serde(default)]
    pub uses: Vec<Pattern>,
    /// Explicit settings of what the runtime would otherwise decide
    /// (cipher suites, named groups), whatever their value.
    #[serde(default)]
    pub settings: Vec<Pattern>,
}

#[derive(Debug)]
pub(crate) struct CompiledNote {
    pub note: Note,
    pub uses: Vec<CompiledPattern>,
    pub settings: Vec<CompiledPattern>,
}

/// A validated, ready-to-evaluate collection of notes.
#[derive(Debug, Default)]
pub struct NoteSet {
    pub(crate) notes: Vec<CompiledNote>,
}

impl NoteSet {
    pub fn compile(notes: impl IntoIterator<Item = Note>) -> Result<Self, RuleError> {
        let mut seen = HashSet::new();
        let mut compiled = Vec::new();
        for note in notes {
            if !seen.insert(note.id.clone()) {
                return Err(RuleError::DuplicateId(note.id));
            }
            compiled.push(compile_note(note)?);
        }
        Ok(Self { notes: compiled })
    }

    pub fn notes(&self) -> impl Iterator<Item = &Note> {
        self.notes.iter().map(|c| &c.note)
    }

    pub fn len(&self) -> usize {
        self.notes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }
}

fn compile_note(note: Note) -> Result<CompiledNote, RuleError> {
    let id = note.id.as_str();
    let require = |value: bool, field| {
        if value {
            Ok(())
        } else {
            Err(RuleError::Empty {
                id: id.to_owned(),
                field,
            })
        }
    };
    require(!id.trim().is_empty(), "id")?;
    require(!note.topic.trim().is_empty(), "topic")?;
    require(!note.text.trim().is_empty(), "text")?;
    require(!note.platforms.is_empty(), "platforms")?;
    require(
        !(note.uses.is_empty() && note.settings.is_empty()),
        "uses or settings",
    )?;
    let uses = compile_patterns(id, &note.uses)?;
    let settings = compile_patterns(id, &note.settings)?;
    Ok(CompiledNote {
        note,
        uses,
        settings,
    })
}

/// What a note found in a place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservationKind {
    /// The topic is in play here.
    Use,
    /// An explicit setting of what the runtime would otherwise decide.
    Setting,
}

/// A place a note matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub note: String,
    pub kind: ObservationKind,
    pub path: String,
    pub location: Location,
}
