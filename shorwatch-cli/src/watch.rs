//! `--watch`: scan again whenever a scanned file changes, until Ctrl+C.
//!
//! Polls modification times instead of subscribing to file system events:
//! no dependency, the same on every platform, and listing a project's files
//! takes milliseconds next to scanning them.

use std::io::{IsTerminal, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

use anyhow::Result;

use crate::args::ScanArgs;
use crate::{discover, output, pipeline};

const POLL: Duration = Duration::from_millis(500);
/// Editors often write a file in several steps; wait for them to finish.
const SETTLE: Duration = Duration::from_millis(150);

type Snapshot = Vec<(PathBuf, Option<SystemTime>, u64)>;

pub fn run(args: &ScanArgs, version: &str) -> Result<ExitCode> {
    let terminal = std::io::stdout().is_terminal();
    let mut open = args.open;
    let mut seen = snapshot(args)?;
    loop {
        let mut stdout = anstream::stdout();
        if terminal {
            // Clear the screen and the scrollback, cursor home: one scan
            // on screen at a time.
            write!(stdout, "\x1b[2J\x1b[3J\x1b[H")?;
            stdout.flush()?;
        }
        if output::wants_banner(args) {
            output::banner(version)?;
        }
        let mut scan = pipeline::run(&args.analysis, version)?;
        output::add_links(&mut scan, args);
        crate::report(&scan, args, open)?;
        open = false;
        writeln!(
            stdout,
            "\n Watching {} files for changes · Ctrl+C to stop",
            seen.len()
        )?;
        stdout.flush()?;
        seen = next_change(args, &seen)?;
    }
}

fn next_change(args: &ScanArgs, seen: &Snapshot) -> Result<Snapshot> {
    loop {
        sleep(POLL);
        if snapshot(args)? != *seen {
            sleep(SETTLE);
            return snapshot(args);
        }
    }
}

/// The scanned files with their modification time and size: a file added,
/// removed, saved or replaced changes it.
fn snapshot(args: &ScanArgs) -> Result<Snapshot> {
    Ok(discover::files(&args.analysis.paths)?
        .into_iter()
        .map(|(path, _)| {
            let metadata = path.metadata().ok();
            let modified = metadata.as_ref().and_then(|m| m.modified().ok());
            let len = metadata.map_or(0, |m| m.len());
            (path, modified, len)
        })
        .collect())
}
