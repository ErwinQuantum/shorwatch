//! The scan itself: read and lower every file in parallel, link the units of
//! each project together (and with the classpath's declarations), analyze
//! each unit in parallel.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use rayon::prelude::*;
use shorwatch_core::{CodeRole, Finding, Library, RuleSet, Severity, SourceUnit, analyze, link};
use shorwatch_report::{Project, Scan, project_of};

use crate::args::Analysis;
use crate::discover::{self, display_path};
use crate::suppress::{self, Baseline};
use crate::{classpath, printable, projects, rules};

/// Everything a scanning command does before reporting: rules, files,
/// classpath, projects, the scan, then the findings ignored in the code or
/// known from the baseline set aside.
pub fn run(analysis: &Analysis, version: &str) -> Result<Scan> {
    let baseline = match &analysis.baseline {
        Some(path) => Some(Baseline::load(path)?),
        None if analysis.no_baseline => None,
        None => {
            let default = Path::new(suppress::DEFAULT_FILE);
            default
                .is_file()
                .then(|| Baseline::load(default))
                .transpose()?
        }
    };
    let mut scan = analyze_all(analysis, version)?;
    printable::scan(&mut scan);
    suppress::apply(&mut scan, baseline.as_ref());
    Ok(scan)
}

/// The scan a baseline records: comments still apply, no older baseline.
pub fn run_for_baseline(analysis: &Analysis, version: &str) -> Result<Scan> {
    let mut scan = analyze_all(analysis, version)?;
    printable::scan(&mut scan);
    suppress::apply(&mut scan, None);
    Ok(scan)
}

fn analyze_all(analysis: &Analysis, version: &str) -> Result<Scan> {
    let rules = rules::load(&analysis.rules)?;
    let mut files = discover::files(&analysis.paths)?;
    if analysis.exclude_tests {
        files.retain(|(_, role)| *role == CodeRole::Production);
    }
    let options = Options {
        min_severity: analysis.min_severity.into(),
        tool_version: version.to_owned(),
    };
    let library = classpath::load(&analysis.classpath)?;
    if !analysis.classpath.is_empty() {
        eprintln!(
            "classpath: {} types, {} methods returning types",
            library.types.len(),
            library.methods.len()
        );
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    let paths: Vec<_> = files.iter().map(|(path, _)| path.clone()).collect();
    let projects = projects::detect(&analysis.paths, &paths, &cwd);
    Ok(scan(&files, projects, &library, &rules, &options))
}

pub struct Options {
    pub min_severity: Severity,
    pub tool_version: String,
}

pub fn scan(
    files: &[(PathBuf, CodeRole)],
    projects: Vec<Project>,
    library: &Library,
    rules: &RuleSet,
    options: &Options,
) -> Scan {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut lowered: Vec<(SourceUnit, Option<String>)> = files
        .par_iter()
        .filter_map(|(path, role)| {
            let (mut unit, source) = lower(path, &cwd)?;
            unit.set_role(*role);
            Some((unit, source))
        })
        .collect();
    // par_iter + collect keeps the input order, so linking is deterministic.
    // Each project is linked on its own: unrelated services share no data
    // flow, and linking them together only costs time.
    let project = |unit: &SourceUnit| project_of(&projects, unit.path());
    lowered.sort_by_key(|(unit, _)| project(unit));
    let (mut units, sources): (Vec<_>, Vec<_>) = lowered.drain(..).unzip();
    let groups: Vec<&mut [SourceUnit]> = units
        .chunk_by_mut(|a, b| project(a) == project(b))
        .collect();
    groups
        .into_par_iter()
        .for_each(|group| link(group, library));

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
        .filter_map(|(unit, source)| Some((unit.path().to_owned(), source?)))
        .collect();
    Scan {
        tool_version: options.tool_version.clone(),
        findings,
        sources,
        files_scanned: units.len(),
        projects,
        links: shorwatch_report::SourceLinks::default(),
        suppressed: Vec::new(),
    }
}

/// Reads and lowers one file, with the text reports show (none for binary
/// files). Unreadable files are reported on stderr and skipped, so one bad
/// file never aborts a scan.
fn lower(path: &Path, cwd: &Path) -> Option<(SourceUnit, Option<String>)> {
    let extension = path.extension()?.to_str()?;
    let frontend = shorwatch_langs::for_extension(extension)?;
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "{}",
                printable::text(&format!("warning: skipping `{}`: {error}", path.display()))
            );
            return None;
        }
    };
    match frontend.lower_bytes(&display_path(path, cwd), bytes) {
        Ok(lowered) => Some(lowered),
        Err(error) => {
            eprintln!(
                "{}",
                printable::text(&format!("warning: skipping `{}`: {error}", path.display()))
            );
            None
        }
    }
}
