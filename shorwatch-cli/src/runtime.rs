//! The notes of a scan: what the runtime decides and the files cannot say,
//! counted once for the whole scan (see `shorwatch_core::Note`).

use rayon::prelude::*;
use shorwatch_core::{NoteSet, ObservationKind, SourceUnit, observe};
use shorwatch_report::RuntimeNote;

/// One entry per note that found anything, in the notes' order: how many
/// places have the topic in play and how many are explicit settings. A note
/// that found nothing says nothing: the topic is not in this scan.
pub fn notes(units: &[SourceUnit], notes: &NoteSet) -> Vec<RuntimeNote> {
    let observations: Vec<_> = units
        .par_iter()
        .flat_map_iter(|unit| observe(unit, notes))
        .collect();
    notes
        .notes()
        .filter_map(|note| {
            let count = |kind| {
                observations
                    .iter()
                    .filter(|o| o.note == note.id && o.kind == kind)
                    .count()
            };
            let (uses, settings) = (count(ObservationKind::Use), count(ObservationKind::Setting));
            (uses + settings > 0).then(|| RuntimeNote {
                id: note.id.clone(),
                topic: note.topic.clone(),
                text: note.text.split_whitespace().collect::<Vec<_>>().join(" "),
                uses,
                settings,
            })
        })
        .collect()
}
