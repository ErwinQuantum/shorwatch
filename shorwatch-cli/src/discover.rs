//! Finding the files to scan: walks the given paths respecting `.gitignore`,
//! skips build output, and keeps files some frontend understands.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;

/// Generated or vendored directories that are not worth scanning even when
/// no `.gitignore` excludes them.
const SKIPPED_DIRS: &[&str] = &["target", "build", "node_modules", ".gradle"];

/// Larger files are almost always generated; parsing them is slow and noisy.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

pub fn files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    for path in paths {
        if !path.exists() {
            bail!("`{}` does not exist", path.display());
        }
    }
    let Some((first, rest)) = paths.split_first() else {
        return Ok(Vec::new());
    };
    let mut builder = WalkBuilder::new(first);
    for path in rest {
        builder.add(path);
    }
    builder.filter_entry(|entry| {
        let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
        !(is_dir && SKIPPED_DIRS.iter().any(|d| entry.file_name() == *d))
    });

    let mut files = Vec::new();
    for entry in builder.build() {
        let entry = entry.context("walking the scan paths")?;
        let path = entry.path();
        let is_file = entry.file_type().is_some_and(|t| t.is_file());
        if is_file && is_supported(path) && !too_large(path) {
            files.push(path.to_owned());
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn is_supported(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| shorwatch_langs::for_extension(e).is_some())
}

fn too_large(path: &Path) -> bool {
    path.metadata().is_ok_and(|m| m.len() > MAX_FILE_BYTES)
}

/// How a scanned file is named in reports: relative to the working directory
/// when possible (clickable from the terminal, stable in SARIF), with `/`
/// separators on every platform.
pub fn display_path(path: &Path, cwd: &Path) -> String {
    let relative = path.strip_prefix(cwd).unwrap_or(path);
    let relative = relative.strip_prefix(".").unwrap_or(relative);
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
