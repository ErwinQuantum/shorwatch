//! Finding the files to scan: walks the given paths respecting `.gitignore`,
//! skips build output, and keeps files some frontend understands, each with
//! its role (production or test code).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;
use shorwatch_core::CodeRole;

use crate::layout;

/// Generated or vendored directories that are not worth scanning even when
/// no `.gitignore` excludes them.
const SKIPPED_DIRS: &[&str] = &["target", "build", "node_modules", ".gradle"];

/// Larger files are almost always generated; parsing them is slow and noisy.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

pub fn files(paths: &[PathBuf]) -> Result<Vec<(PathBuf, CodeRole)>> {
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
            files.push((path.to_owned(), role(path, paths)));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files.dedup_by(|a, b| a.0 == b.0);
    Ok(files)
}

/// The role of `path`, judged by its path inside the scan root it was found
/// under (the most specific one when roots nest).
fn role(path: &Path, roots: &[PathBuf]) -> CodeRole {
    let relative = roots
        .iter()
        .filter_map(|root| path.strip_prefix(root).ok())
        .min_by_key(|relative| relative.components().count())
        .unwrap_or(path);
    layout::role(relative)
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
    // Not by joining components: a Windows root would come out as `C:/\/`.
    relative.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_relative_to_the_working_directory_with_slashes() {
        let cwd = Path::new("/work");
        assert_eq!(
            display_path(Path::new("/work/src/A.java"), cwd),
            "src/A.java"
        );
        assert_eq!(display_path(Path::new("./src/A.java"), cwd), "src/A.java");
    }

    #[cfg(windows)]
    #[test]
    fn windows_absolute_paths_outside_it_keep_their_drive() {
        let cwd = Path::new(r"D:\work");
        assert_eq!(
            display_path(Path::new(r"C:\Users\dev\A.java"), cwd),
            "C:/Users/dev/A.java"
        );
    }
}
