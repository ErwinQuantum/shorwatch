//! Opening HTML reports in the default browser. Terminals (VS Code's among
//! them) may open a `file://` link as a text file in an editor; asking the
//! system to open the file reaches the browser instead.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Where reports written for the terminal live, with the pointer to the
/// last one written.
pub fn folder() -> PathBuf {
    std::env::temp_dir().join("shorwatch")
}

fn last_report() -> PathBuf {
    folder().join("last-report")
}

/// Records the report for `shorwatch open`. Best effort: a scan never fails
/// because of it.
pub fn remember(report: &Path) {
    if let Ok(path) = fs::canonicalize(report) {
        let path = path.to_string_lossy();
        // Windows' verbatim prefix (`\\?\C:\...`), which not every program
        // opening the file understands.
        let path = path.strip_prefix(r"\\?\").unwrap_or(&path);
        let _ = fs::create_dir_all(folder());
        let _ = fs::write(last_report(), path.as_bytes());
    }
}

/// `shorwatch open`: the given report, or the last one written.
pub fn open_last(report: Option<&Path>) -> Result<()> {
    let path = match report {
        Some(path) => path.to_path_buf(),
        None => match fs::read_to_string(last_report()) {
            Ok(path) => PathBuf::from(path.trim()),
            Err(_) => bail!("no report yet: run `shorwatch scan` first"),
        },
    };
    if !path.is_file() {
        bail!("`{}` does not exist", path.display());
    }
    open(&path)
}

pub fn open(report: &Path) -> Result<()> {
    let mut command = if cfg!(windows) {
        // Not `cmd /c start`: cmd would interpret `&` or `^` in the path.
        let mut command = Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    } else if cfg!(target_os = "macos") {
        Command::new("open")
    } else {
        Command::new("xdg-open")
    };
    let status = command
        .arg(report)
        .status()
        .with_context(|| format!("opening `{}` in the browser", report.display()))?;
    if !status.success() {
        bail!("could not open `{}` in the browser", report.display());
    }
    Ok(())
}
