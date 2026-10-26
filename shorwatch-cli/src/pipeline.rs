//! The scan itself: read and lower every file in parallel, link the units of
//! the project together, analyze each unit in parallel.

use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use shorwatch_core::{Finding, RuleSet, Severity, SourceUnit, analyze, link};
use shorwatch_report::Scan;

use crate::discover::display_path;

pub struct Options {
    pub min_severity: Severity,
    pub tool_version: String,
}

pub fn scan(files: &[PathBuf], rules: &RuleSet, options: &Options) -> Scan {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut lowered: Vec<(SourceUnit, String)> = files
        .par_iter()
        .filter_map(|path| lower(path, &cwd))
        .collect();
    // par_iter + collect keeps the input order, so linking is deterministic.
    let (mut units, sources): (Vec<_>, Vec<_>) = lowered.drain(..).unzip();
    link(&mut units);

    let mut findings: Vec<Finding> = units
        .par_iter()
        .flat_map_iter(|unit| analyze(unit, rules))
        .filter(|f| f.severity >= options.min_severity)
        .collect();
    findings.sort_by(|a, b| {
        (&a.path, a.location.start, &a.rule_id).cmp(&(&b.path, b.location.start, &b.rule_id))
    });

    let sources = units
        .iter()
        .zip(sources)
        .filter(|(unit, _)| findings.iter().any(|f| f.path == unit.path()))
        .map(|(unit, source)| (unit.path().to_owned(), source))
        .collect();
    Scan {
        tool_version: options.tool_version.clone(),
        findings,
        sources,
        files_scanned: units.len(),
    }
}

/// Reads and lowers one file. Unreadable or non-UTF-8 files are reported on
/// stderr and skipped, so one bad file never aborts a scan.
fn lower(path: &Path, cwd: &Path) -> Option<(SourceUnit, String)> {
    let extension = path.extension()?.to_str()?;
    let frontend = shorwatch_langs::for_extension(extension)?;
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
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
