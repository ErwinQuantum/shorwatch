//! The scan itself: read and lower every file in parallel, link the units of
//! the project together (and with the classpath's declarations), analyze each
//! unit in parallel.

use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use shorwatch_core::{CodeRole, Finding, Library, RuleSet, Severity, SourceUnit, analyze, link};
use shorwatch_report::Scan;

use crate::discover::display_path;

pub struct Options {
    pub min_severity: Severity,
    pub tool_version: String,
}

pub fn scan(
    files: &[(PathBuf, CodeRole)],
    library: &Library,
    rules: &RuleSet,
    options: &Options,
) -> Scan {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut lowered: Vec<(SourceUnit, String)> = files
        .par_iter()
        .filter_map(|(path, role)| {
            let (mut unit, source) = lower(path, &cwd)?;
            unit.set_role(*role);
            Some((unit, source))
        })
        .collect();
    // par_iter + collect keeps the input order, so linking is deterministic.
    let (mut units, sources): (Vec<_>, Vec<_>) = lowered.drain(..).unzip();
    link(&mut units, library);

    let mut findings: Vec<Finding> = units
        .par_iter()
        .flat_map_iter(|unit| analyze(unit, rules))
        .filter(|f| f.severity >= options.min_severity)
        .collect();
    findings.sort_by(|a, b| {
        (&a.path, a.location.start, &a.rule_id).cmp(&(&b.path, b.location.start, &b.rule_id))
    });

    // Files with findings, and the files their data-flow paths go through.
    let shown = |path: &str| {
        findings
            .iter()
            .any(|f| f.path == path || f.flow.iter().any(|s| s.path.as_deref() == Some(path)))
    };
    let sources = units
        .iter()
        .zip(sources)
        .filter(|(unit, _)| shown(unit.path()))
        .map(|(unit, source)| (unit.path().to_owned(), source))
        .collect();
    Scan {
        tool_version: options.tool_version.clone(),
        findings,
        sources,
        files_scanned: units.len(),
    }
}

/// Reads and lowers one file. Unreadable files are reported on stderr and
/// skipped, so one bad file never aborts a scan.
fn lower(path: &Path, cwd: &Path) -> Option<(SourceUnit, String)> {
    let extension = path.extension()?.to_str()?;
    let frontend = shorwatch_langs::for_extension(extension)?;
    let source = match fs::read(path) {
        Ok(bytes) => decode(bytes),
        Err(error) => {
            eprintln!("warning: skipping `{}`: {error}", path.display());
            return None;
        }
    };
    match frontend.lower(&display_path(path, cwd), &source) {
        Ok(unit) => Some((unit, source)),
        Err(error) => {
            eprintln!("warning: skipping `{}`: {error}", path.display());
            None
        }
    }
}

/// UTF-8, or else ISO-8859-1: the historical encoding of `.properties` files
/// and of older Java sources. Every byte is a Latin-1 character, so decoding
/// never fails; algorithm names and keys are ASCII either way.
fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| error.into_bytes().into_iter().map(char::from).collect())
}
