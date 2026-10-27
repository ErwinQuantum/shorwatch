//! Rendering the scan in the chosen format and writing it out.

use std::fs;
use std::io::{IsTerminal, Write};
use std::path::Path;

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

pub fn write(scan: &Scan, args: &ScanArgs) -> Result<()> {
    let report = match args.format {
        Format::Text => terminal::render(
            scan,
            terminal::Options {
                view: if args.compact {
                    terminal::View::Compact
                } else if args.details {
                    terminal::View::Details
                } else {
                    terminal::View::Overview
                },
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

fn to_file(path: &Path, report: &str) -> Result<()> {
    let plain = anstream::adapter::strip_str(report).to_string();
    fs::write(path, plain).with_context(|| format!("writing `{}`", path.display()))
}
