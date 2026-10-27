//! Opening HTML reports in the default browser. Terminals (VS Code's among
//! them) may open a `file://` link as a text file in an editor; asking the
//! system to open the file reaches the browser instead.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Where reports written for the terminal live, with the pointer to the
/// last one written. Per user: on Unix `/tmp` is shared, and another user
/// could plant the folder, the pointer or a symlink where a report goes.
pub fn folder() -> PathBuf {
    if cfg!(windows) {
        // %TEMP% is already per user.
        return std::env::temp_dir().join("shorwatch");
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            let home = PathBuf::from(std::env::var_os("HOME")?);
            Some(if cfg!(target_os = "macos") {
                home.join("Library/Caches")
            } else {
                home.join(".cache")
            })
        });
    cache.unwrap_or_else(std::env::temp_dir).join("shorwatch")
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
    if let Some(path) = report {
        if !path.is_file() {
            bail!("`{}` does not exist", path.display());
        }
        return open(path);
    }
    let Ok(last) = fs::read_to_string(last_report()) else {
        bail!("no report yet: run `shorwatch` or `shorwatch report` first");
    };
    let path = PathBuf::from(last.trim());
    if !path.is_file() {
        bail!(
            "the last report, `{}`, no longer exists: run `shorwatch` again",
            path.display()
        );
    }
    open(&path)
}

pub fn open(report: &Path) -> Result<()> {
    // The system opens a file with whatever handles its type: an `.exe` or
    // a script would run. Reports only.
    let html = report
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm"));
    if !html {
        bail!("`{}` is not an HTML report", report.display());
    }
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
