//! Findings left out of a scan's results on purpose, and the fingerprint
//! that recognises a finding across scans (line numbers move; the code on
//! the line rarely does).

use serde::{Deserialize, Serialize};
use shorwatch_core::Finding;

use crate::Scan;

/// A finding the scan found but does not report as a result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suppressed {
    #[serde(flatten)]
    pub finding: Finding,
    pub suppression: Suppression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Suppression {
    /// A `shorwatch:ignore` comment at the finding.
    InSource { justification: Option<String> },
    /// Already there when the baseline was recorded.
    Baseline,
}

/// Identifies a finding across scans: its rule and the code it is on
/// (whitespace-insensitive), or the key a binary file holds. Not its line
/// number, which edits elsewhere in the file change.
pub fn fingerprint(scan: &Scan, finding: &Finding) -> String {
    let content = match scan.line(&finding.path, finding.location.start.line) {
        Some(line) => line.split_whitespace().collect::<Vec<_>>().join(" "),
        None => finding.detail.clone().unwrap_or_default(),
    };
    format!(
        "{:016x}",
        fnv1a(&[finding.rule_id.as_bytes(), b"\0", content.as_bytes()])
    )
}

/// FNV-1a, 64 bits: stable across versions and platforms, unlike std's
/// hasher, and enough to tell findings apart within one file.
fn fnv1a(parts: &[&[u8]]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in parts.iter().flat_map(|part| part.iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn fingerprints_ignore_line_numbers_and_indentation() {
        let mut scan = scan();
        let finding = scan.findings[0].clone();
        let before = fingerprint(&scan, &finding);
        // The same code, re-indented and two lines further down.
        let source = scan.sources.get_mut(&finding.path).unwrap();
        let line = source
            .lines()
            .nth(finding.location.start.line as usize - 1)
            .unwrap()
            .trim()
            .to_owned();
        *source = format!("\n\n{}", source.replace(&line, &format!("        {line}")));
        let mut moved = finding.clone();
        moved.location.start.line += 2;
        assert_eq!(fingerprint(&scan, &moved), before);
    }

    #[test]
    fn fingerprints_differ_by_rule_and_code() {
        let scan = scan();
        let [a, b] = [&scan.findings[0], &scan.findings[1]];
        assert_ne!(fingerprint(&scan, a), fingerprint(&scan, b));
    }

    #[test]
    fn fnv1a_is_the_reference_function() {
        assert_eq!(fnv1a(&[b""]), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(&[b"a"]), 0xaf63_dc4c_8601_ec8c);
    }
}
