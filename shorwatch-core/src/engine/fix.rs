//! Mechanical fixes for the matched argument (Grover-category rules only).

use super::Match;
use crate::finding::SuggestedFix;
use crate::rule::CompiledRule;

pub(super) fn suggested_fix(rule: &CompiledRule, matched: &Match) -> Option<SuggestedFix> {
    let fix = rule.fix.as_ref()?;
    let arg = matched.arg?;
    if arg.resolved_via.is_some() || !fix.replace.is_match(&arg.raw) {
        return None;
    }
    Some(SuggestedFix {
        description: fix.description.clone(),
        location: arg.location,
        replacement: fix
            .replace
            .replace_all(&arg.raw, fix.with.as_str())
            .into_owned(),
    })
}
