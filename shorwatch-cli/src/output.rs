//! Rendering the scan in the chosen format and writing it out.

use std::fmt::Write as _;
use std::fs;
use std::io::{IsTerminal, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use shorwatch_report::{Scan, cbom, html, json, markdown, sarif, terminal};

use crate::args::{Format, ScanArgs};

/// The banner only greets people: never when the output is piped, redirected
/// to a file or machine-readable.
pub fn wants_banner(args: &ScanArgs) -> bool {
    args.format == Format::Text
        && args.output.is_none()
        && !args.no_banner
        && std::io::stdout().is_terminal()
}

pub fn banner(version: &str) -> Result<()> {
    let mut stdout = anstream::stdout();
    writeln!(stdout, "{}", terminal::banner(version))?;
    Ok(())
}

/// The HTML report of a scan: the local file, if any, and the link to show
/// for it: `--report-url`, or the file as a `file://` URL.
pub struct HtmlReport {
    pub path: Option<PathBuf>,
    pub link: Option<String>,
}

/// Writes the HTML report where it was asked for (or, for someone reading
/// the text report on a terminal or asking to `--open` it, to a temporary
/// folder). With `--format html` the report itself is written by [`write`].
pub fn html_report(scan: &Scan, args: &ScanArgs) -> Result<HtmlReport> {
    let path = if let Some(path) = &args.html {
        Some(path.clone())
    } else if args.format == Format::Html {
        args.output.clone()
    } else if wants_temporary_html(scan, args) {
        Some(temporary_html(scan, args)?)
    } else {
        None
    };
    if let Some(path) = &path
        && args.format != Format::Html
    {
        fs::write(path, html::render(scan))
            .with_context(|| format!("writing `{}`", path.display()))?;
    }
    let link = args
        .gate
        .report_url
        .clone()
        .or_else(|| path.as_deref().map(file_url));
    Ok(HtmlReport { path, link })
}

fn wants_temporary_html(scan: &Scan, args: &ScanArgs) -> bool {
    let reading = args.format == Format::Text
        && args.output.is_none()
        && !scan.findings.is_empty()
        && std::io::stdout().is_terminal();
    !args.no_html && (args.open || reading)
}

/// One file per scanned folder, overwritten by the next scan of it.
fn temporary_html(scan: &Scan, args: &ScanArgs) -> Result<PathBuf> {
    let folder = crate::browser::folder();
    fs::create_dir_all(&folder).with_context(|| format!("creating `{}`", folder.display()))?;
    let name = match scan.projects.as_slice() {
        [project] => project.name.clone(),
        _ => args
            .analysis
            .paths
            .first()
            .and_then(|path| fs::canonicalize(path).ok())
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default(),
    };
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = if name.is_empty() { "scan".into() } else { name };
    Ok(folder.join(format!("{name}.html")))
}

/// A `file://` URL that terminals turn into a link.
pub fn file_url(path: &Path) -> String {
    let absolute = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = absolute.to_string_lossy().replace('\\', "/");
    // Windows' verbatim prefix (`\\?\C:\...`).
    let text = text.strip_prefix("//?/").unwrap_or(&text);
    let mut url = String::from(if text.starts_with('/') {
        "file://"
    } else {
        "file:///"
    });
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/:-_.~".contains(&byte) {
            url.push(char::from(byte));
        } else {
            let _ = write!(url, "%{byte:02X}");
        }
    }
    url
}

pub fn write(scan: &Scan, args: &ScanArgs, html: &HtmlReport) -> Result<()> {
    let report = match args.format {
        Format::Text => terminal::render(
            scan,
            &terminal::Options {
                view: if args.compact {
                    terminal::View::Compact
                } else if args.details {
                    terminal::View::Details
                } else if args.overview {
                    terminal::View::Overview
                } else {
                    terminal::View::Summary
                },
                report: html.link.clone(),
                opened: args.open,
                ci: false,
            },
        ),
        Format::Sarif => sarif::render(scan),
        Format::Cbom => cbom::render(scan),
        Format::Json => json::render(scan),
        Format::Markdown => markdown::render(scan),
        Format::Html => html::render(scan),
    };
    match &args.output {
        Some(path) => to_file(path, &report),
        None => {
            // anstream drops colours when stdout is not a terminal or
            // NO_COLOR is set.
            let mut stdout = anstream::stdout();
            stdout.write_all(report.as_bytes())?;
            stdout.flush()?;
            Ok(())
        }
    }
}

/// Why the scan fails, on standard error so it shows in CI logs whatever
/// the format, with the report link when the text report did not show it.
pub fn verdict(failing: usize, args: &ScanArgs, report_link: Option<&str>) -> Result<()> {
    let shown = args.format == Format::Text && args.output.is_none();
    let link = report_link.filter(|_| !shown);
    let mut stderr = anstream::stderr();
    write!(stderr, "{}", terminal::verdict(failing, link))?;
    Ok(())
}

fn to_file(path: &Path, report: &str) -> Result<()> {
    let plain = anstream::adapter::strip_str(report).to_string();
    fs::write(path, plain).with_context(|| format!("writing `{}`", path.display()))
}
