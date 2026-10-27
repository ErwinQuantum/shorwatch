//! The default terminal view: what a scan found at a glance, not every
//! finding. One line per file (grouped by project when there are several),
//! the most urgent findings explained, then the summary and where to look
//! next. `--details` lists everything; the HTML report is for browsing.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use shorwatch_core::{CodeRole, Finding, Severity, Status};

use super::detailed;
use super::style::{accent, bold, dim, paint, severity_mark};
use crate::Scan;

/// Findings explained in full below the file list.
const URGENT: usize = 3;
/// Up to this many findings, all are explained and no file list is needed.
const FEW: usize = 3;
const FILES_ONE_PROJECT: usize = 20;
const FILES_PER_PROJECT: usize = 8;
const PATH_WIDTH: usize = 58;
const ALGORITHMS_WIDTH: usize = 40;

pub(super) fn render(scan: &Scan) -> String {
    let mut out = String::new();
    if scan.findings.len() <= FEW {
        let blocks: Vec<_> = scan
            .findings
            .iter()
            .map(|f| detailed::render(scan, f))
            .collect();
        out.push_str(&blocks.join("\n"));
        return out;
    }
    if scan.projects.len() > 1 {
        projects(scan, &mut out);
    } else {
        let root = scan.projects.first().map_or("", |p| p.root.as_str());
        let _ = writeln!(out, "{}", paint(" Files with findings", bold()));
        files(
            scan.findings.iter().collect(),
            root,
            FILES_ONE_PROJECT,
            &mut out,
        );
    }

    let mut urgent: Vec<&Finding> = scan.findings.iter().collect();
    urgent.sort_by_key(|f| {
        (
            f.role == CodeRole::Test,
            Reverse(f.severity),
            f.status == Status::InTransition,
        )
    });
    let _ = writeln!(
        out,
        "\n{} {}\n",
        paint(" Most urgent ", accent()),
        paint(format!("{URGENT} of {}", scan.findings.len()), dim())
    );
    // Different algorithms first: three RSA findings say less than RSA,
    // ECDSA and SHA-1.
    let mut picked: Vec<&Finding> = Vec::new();
    for finding in &urgent {
        if picked.len() < URGENT && picked.iter().all(|p| p.algorithm != finding.algorithm) {
            picked.push(finding);
        }
    }
    for finding in &urgent {
        if picked.len() < URGENT && !picked.iter().any(|p| std::ptr::eq(*p, *finding)) {
            picked.push(finding);
        }
    }
    let blocks: Vec<_> = picked.iter().map(|f| detailed::render(scan, f)).collect();
    out.push_str(&blocks.join("\n"));
    out
}

/// Where to look next, after the summary.
pub(super) fn hints(scan: &Scan) -> String {
    if scan.findings.len() <= FEW {
        return String::new();
    }
    let arrow = paint("→", accent());
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n {arrow} {}  every finding, explained",
        paint("--details", bold())
    );
    let _ = writeln!(
        out,
        " {arrow} {}  a report to browse{}",
        paint("--format html -o shorwatch.html", bold()),
        if scan.projects.len() > 1 {
            ", one tab per project"
        } else {
            ""
        }
    );
    out
}

fn projects(scan: &Scan, out: &mut String) {
    let mut by_project: BTreeMap<usize, Vec<&Finding>> = BTreeMap::new();
    for finding in &scan.findings {
        if let Some(index) = scan.project_of(&finding.path) {
            by_project.entry(index).or_default().push(finding);
        }
    }
    let mut order: Vec<usize> = (0..scan.projects.len()).collect();
    order.sort_by_key(|i| {
        let findings = by_project.get(i).map_or(&[][..], Vec::as_slice);
        (
            Reverse(findings.iter().map(|f| f.severity).max()),
            Reverse(findings.len()),
            scan.projects[*i].name.clone(),
        )
    });
    let width = scan
        .projects
        .iter()
        .map(|p| p.name.chars().count())
        .max()
        .unwrap_or(0);
    let mut clean = Vec::new();
    for index in order {
        let project = &scan.projects[index];
        let findings = by_project.remove(&index).unwrap_or_default();
        if findings.is_empty() {
            clean.push(format!(
                "{} {}",
                project.name,
                paint(
                    format!("({})", plural(project.files_scanned, "file")),
                    dim()
                )
            ));
            continue;
        }
        let worst = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        let transition = findings.iter().all(|f| f.status == Status::InTransition);
        let _ = writeln!(
            out,
            "{} {} {}  {}",
            if out.is_empty() { "" } else { "\n" },
            severity_mark(worst, transition),
            paint(format!("{:<width$}", project.name), bold()),
            counts(&findings),
        );
        files(findings, &project.root, FILES_PER_PROJECT, out);
    }
    // Clean projects only need naming, all on one line.
    if !clean.is_empty() {
        let _ = writeln!(
            out,
            "{} {} {}  {}",
            if out.is_empty() { "" } else { "\n" },
            paint("✓", accent()),
            paint("clean", bold()),
            clean.join(", ")
        );
    }
}

/// `4 findings · 3 high · 1 medium`.
fn counts(findings: &[&Finding]) -> String {
    let mut by_severity: BTreeMap<Reverse<Severity>, usize> = BTreeMap::new();
    for finding in findings {
        *by_severity.entry(Reverse(finding.severity)).or_default() += 1;
    }
    let severities: Vec<String> = by_severity
        .iter()
        .map(|(Reverse(s), n)| format!("{n} {}", crate::summary::severity_label(*s)))
        .collect();
    let tests = findings.iter().filter(|f| f.role == CodeRole::Test).count();
    let roles = match tests {
        0 => String::new(),
        n if n == findings.len() => " · all in tests".to_owned(),
        n => format!(" · {} in production", findings.len() - n),
    };
    format!(
        "{}{} {}",
        plural(findings.len(), "finding"),
        roles,
        paint(format!("· {}", severities.join(" · ")), dim())
    )
}

/// One line per file: its worst severity, path, count and algorithms. The
/// most severe files first, at most `limit`.
fn files(findings: Vec<&Finding>, root: &str, limit: usize, out: &mut String) {
    let mut by_file: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        by_file.entry(&finding.path).or_default().push(finding);
    }
    let mut rows: Vec<(&str, Vec<&Finding>)> = by_file.into_iter().collect();
    // What ships before tests, what is still vulnerable before what is
    // already migrating, then the most severe.
    rows.sort_by_key(|(path, fs)| {
        (
            fs.iter().all(|f| f.role == CodeRole::Test),
            fs.iter().all(|f| f.status == Status::InTransition),
            Reverse(fs.iter().map(|f| f.severity).max()),
            Reverse(fs.len()),
            *path,
        )
    });
    let shown: Vec<_> = rows.iter().take(limit).collect();
    let paths: Vec<String> = shown
        .iter()
        .map(|(path, _)| shorten(relative(path, root), PATH_WIDTH))
        .collect();
    let width = paths.iter().map(|p| p.chars().count()).max().unwrap_or(0);
    for ((_, findings), path) in shown.iter().zip(&paths) {
        let worst = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        let transition = findings.iter().all(|f| f.status == Status::InTransition);
        let test = findings.iter().all(|f| f.role == CodeRole::Test);
        let _ = writeln!(
            out,
            "   {} {:<width$}  {:>3}  {}{}",
            severity_mark(worst, transition),
            path,
            findings.len(),
            algorithms(findings),
            if test {
                paint("  test", dim())
            } else {
                String::new()
            },
        );
    }
    if rows.len() > shown.len() {
        let _ = writeln!(
            out,
            "   {}",
            paint(
                format!("… {} more", plural(rows.len() - shown.len(), "file")),
                dim()
            )
        );
    }
}

/// `RSA ×2, SHA-1`, most frequent first, cut to fit.
fn algorithms(findings: &[&Finding]) -> String {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for finding in findings {
        match counts.iter_mut().find(|(a, _)| *a == finding.algorithm) {
            Some((_, n)) => *n += 1,
            None => counts.push((&finding.algorithm, 1)),
        }
    }
    counts.sort_by_key(|(a, n)| (Reverse(*n), *a));
    let names: Vec<String> = counts
        .iter()
        .map(|(a, n)| {
            if *n > 1 {
                format!("{a} ×{n}")
            } else {
                (*a).to_owned()
            }
        })
        .collect();
    paint(shorten_end(&names.join(", "), ALGORITHMS_WIDTH), dim())
}

fn relative<'p>(path: &'p str, root: &str) -> &'p str {
    if root.is_empty() {
        return path;
    }
    path.strip_prefix(root)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(path)
}

/// `src/main/java/…/auth/Config.java`: whole directories from both ends of a
/// long path, the file name always kept.
fn shorten(path: &str, width: usize) -> String {
    if path.chars().count() <= width {
        return path.to_owned();
    }
    let segments: Vec<&str> = path.split('/').collect();
    let fits = |s: &String| s.chars().count() <= width;
    for head in (0..=3.min(segments.len() - 1)).rev() {
        let mut tail = segments.len() - 1;
        let build = |tail: usize| {
            let mut parts: Vec<&str> = segments[..head].to_vec();
            parts.push("…");
            parts.extend(&segments[tail..]);
            parts.join("/")
        };
        if !fits(&build(tail)) {
            continue;
        }
        while tail > head + 1 && fits(&build(tail - 1)) {
            tail -= 1;
        }
        return build(tail);
    }
    let name = segments[segments.len() - 1];
    shorten_end(name, width)
}

fn shorten_end(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let cut: String = text.chars().take(width - 1).collect();
    format!("{cut}…")
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("{n} {word}")
    } else {
        format!("{n} {word}s")
    }
}
