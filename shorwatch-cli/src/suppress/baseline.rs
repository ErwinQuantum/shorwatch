//! `shorwatch-baseline.json`: the findings a project already had when it
//! started using Shorwatch, so scans fail only on new ones. A finding is
//! known by its rule, file and fingerprint (the code on its line), so it
//! stays known when lines above it change.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use shorwatch_report::{Scan, fingerprint};

/// Read from the working directory when present.
pub const DEFAULT_FILE: &str = "shorwatch-baseline.json";
const VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    version: u32,
    findings: Vec<Entry>,
}

/// `line` and `algorithm` only help people reading the file.
#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    rule_id: String,
    path: String,
    fingerprint: String,
    #[serde(default)]
    line: u32,
    #[serde(default)]
    algorithm: String,
}

pub type Key = (String, String, String);

impl Baseline {
    /// Every finding the scan reports.
    pub fn of(scan: &Scan) -> Self {
        let mut findings: Vec<Entry> = scan
            .findings
            .iter()
            .map(|f| Entry {
                rule_id: f.rule_id.clone(),
                path: f.path.clone(),
                fingerprint: fingerprint(scan, f),
                line: f.location.start.line,
                algorithm: f.algorithm.clone(),
            })
            .collect();
        findings.sort_by(|a, b| (&a.path, a.line, &a.rule_id).cmp(&(&b.path, b.line, &b.rule_id)));
        Self {
            version: VERSION,
            findings,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;
        let baseline: Self = serde_json::from_str(&text)
            .with_context(|| format!("`{}` is not a Shorwatch baseline", path.display()))?;
        if baseline.version != VERSION {
            bail!(
                "`{}` is a version {} baseline; this Shorwatch reads version {VERSION}: record it again with `shorwatch baseline`",
                path.display(),
                baseline.version
            );
        }
        Ok(baseline)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a baseline serializes") + "\n"
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// How many times each finding is known: two identical lines in one
    /// file are two findings.
    pub fn counts(&self) -> HashMap<Key, usize> {
        let mut counts = HashMap::new();
        for entry in &self.findings {
            *counts
                .entry((
                    entry.rule_id.clone(),
                    entry.path.clone(),
                    entry.fingerprint.clone(),
                ))
                .or_default() += 1;
        }
        counts
    }
}
