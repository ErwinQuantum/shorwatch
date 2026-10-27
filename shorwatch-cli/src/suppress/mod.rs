//! Findings left out of the results on purpose: ignored in the code
//! (`shorwatch:ignore`), or already in the baseline. They move to
//! [`Scan::suppressed`], where every report counts them.

mod baseline;
mod inline;
#[cfg(test)]
mod tests;

use shorwatch_report::{Scan, Suppressed, Suppression, fingerprint};

pub use baseline::{Baseline, DEFAULT_FILE};

/// Comments first, so an ignored finding keeps its reason even when the
/// baseline knows it too.
pub fn apply(scan: &mut Scan, baseline: Option<&Baseline>) {
    let mut known = baseline.map(Baseline::counts).unwrap_or_default();
    for finding in std::mem::take(&mut scan.findings) {
        let line = finding.location.start.line;
        let comment = inline::suppression(
            &finding,
            scan.line(&finding.path, line),
            line.checked_sub(1)
                .and_then(|above| scan.line(&finding.path, above)),
        );
        let suppression = comment.or_else(|| {
            let key = (
                finding.rule_id.clone(),
                finding.path.clone(),
                fingerprint(scan, &finding),
            );
            let count = known.get_mut(&key).filter(|n| **n > 0)?;
            *count -= 1;
            Some(Suppression::Baseline)
        });
        match suppression {
            Some(suppression) => scan.suppressed.push(Suppressed {
                finding,
                suppression,
            }),
            None => scan.findings.push(finding),
        }
    }
}
