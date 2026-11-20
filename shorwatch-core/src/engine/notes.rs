//! Evaluating notes: where each one's topic is in play, or set explicitly.

use crate::ir::SourceUnit;
use crate::rule::{NoteSet, Observation, ObservationKind};

use super::matching::match_pattern;

/// The places in the unit where a note's patterns match, ordered by position,
/// then note id. A place that is an explicit setting is not also reported as
/// a use: the setting says more.
pub fn observe(unit: &SourceUnit, notes: &NoteSet) -> Vec<Observation> {
    let platform = unit.language().platform();
    let mut found = Vec::new();
    for compiled in notes
        .notes
        .iter()
        .filter(|n| n.note.platforms.contains(&platform))
    {
        for fact in unit.facts() {
            let matches = |patterns: &[_]| {
                patterns
                    .iter()
                    .any(|p| match_pattern(p, fact, unit).is_some())
            };
            let kind = if matches(&compiled.settings) {
                ObservationKind::Setting
            } else if matches(&compiled.uses) {
                ObservationKind::Use
            } else {
                continue;
            };
            found.push(Observation {
                note: compiled.note.id.clone(),
                kind,
                path: unit.path().to_owned(),
                location: fact.location,
            });
        }
    }
    found.sort_by(|a, b| (a.location.start, &a.note).cmp(&(b.location.start, &b.note)));
    found
}
