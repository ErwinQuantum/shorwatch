//! Post-quantum markers next to a finding, which make it `in_transition`.

use crate::finding::HybridEvidence;
use crate::ir::{Fact, FactKind, SourceUnit};
use crate::rule::{CompiledMarker, CompiledRule};

pub(super) fn hybrid_evidence(
    unit: &SourceUnit,
    rule: &CompiledRule,
    fact: &Fact,
) -> Option<HybridEvidence> {
    if rule.markers.is_empty() {
        return None;
    }
    let region = unit.enclosing(fact.scope, rule.hybrid_scope);
    unit.facts().iter().find_map(|other| {
        let in_region = unit.is_within(other.scope, region);
        let text = rule
            .markers
            .iter()
            .find_map(|marker| match (marker, &other.kind) {
                // Imports are file-wide, so they count regardless of the region.
                (CompiledMarker::Import(re), FactKind::Import { path }) => {
                    re.is_match(path).then_some(path.as_str())
                }
                (
                    CompiledMarker::Literal(re),
                    FactKind::Literal { value, .. } | FactKind::Property { value, .. },
                ) if in_region => re.is_match(value).then_some(value.as_str()),
                (
                    CompiledMarker::Type(re),
                    FactKind::Construct { ty, .. } | FactKind::Field { owner: ty, .. },
                ) if in_region => re.is_match(ty.best_name()).then_some(ty.best_name()),
                (
                    CompiledMarker::Type(re),
                    FactKind::Call {
                        receiver: Some(ty), ..
                    },
                ) if in_region => re.is_match(ty.best_name()).then_some(ty.best_name()),
                _ => None,
            })?;
        Some(HybridEvidence {
            text: text.to_owned(),
            location: other.location,
        })
    })
}
