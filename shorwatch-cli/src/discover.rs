//! Finding the files to scan: walks the given paths respecting `.gitignore`
//! and `.shorwatchignore`,
//! skips build output, and keeps files some frontend understands, each with
//! its role (production or test code).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;
use shorwatch_core::CodeRole;

use crate::layout;

/// Generated or vendored directories that are not worth scanning even when
/// no `.gitignore` excludes them.
/// `bin` and `obj` are .NET's build output (generated sources, copied configuration).
const SKIPPED_DIRS: &[&str] = &["target", "build", "node_modules", ".gradle", "bin", "obj"];

/// Suffixes of the files .NET tooling generates (Entity Framework migrations,
/// designer files, source generators): hundreds of kilobytes of fluent code
/// that no one wrote and that makes no cryptographic choice.
const GENERATED_SUFFIXES: &[&str] = &[
    ".Designer.cs",
    ".g.cs",
    ".g.i.cs",
    ".generated.cs",
    "ModelSnapshot.cs",
];

/// Larger files are almost always generated; parsing them is slow and noisy.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// What a walk found: the files to scan, and the source files it passed by
/// because no frontend reads their language, counted per language.
#[derive(Debug, Default)]
pub struct Discovered {
    pub files: Vec<(PathBuf, CodeRole)>,
    pub unanalyzed: BTreeMap<&'static str, usize>,
}

pub fn files(paths: &[PathBuf]) -> Result<Vec<(PathBuf, CodeRole)>> {
    Ok(discover(paths)?.files)
}

pub fn discover(paths: &[PathBuf]) -> Result<Discovered> {
    for path in paths {
        if !path.exists() {
            bail!("`{}` does not exist", path.display());
        }
    }
    let Some((first, rest)) = paths.split_first() else {
        return Ok(Discovered::default());
    };
    let mut builder = WalkBuilder::new(first);
    for path in rest {
        builder.add(path);
    }
    // Files a project never wants scanned (test certificates, vendored
    // code), in `.gitignore` syntax.
    builder.add_custom_ignore_filename(".shorwatchignore");
    builder.filter_entry(|entry| {
        let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
        !(is_dir && SKIPPED_DIRS.iter().any(|d| entry.file_name() == *d))
    });

    let mut files = Vec::new();
    let mut unanalyzed = BTreeMap::new();
    for entry in builder.build() {
        let entry = entry.context("walking the scan paths")?;
        let path = entry.path();
        let is_file = entry.file_type().is_some_and(|t| t.is_file());
        if !is_file {
            continue;
        }
        if is_supported(path) {
            if !is_generated(path) && !too_large(path) {
                files.push((path.to_owned(), role(path, paths)));
            }
        } else if let Some(language) = shorwatch_langs::unsupported_language(path) {
            *unanalyzed.entry(language).or_insert(0) += 1;
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files.dedup_by(|a, b| a.0 == b.0);
    Ok(Discovered { files, unanalyzed })
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
    shorwatch_langs::for_path(path).is_some()
}

fn is_generated(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            GENERATED_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(suffix))
        })
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
    fn generated_dotnet_files_are_skipped() {
        for generated in [
            "M/20260101_Init.Designer.cs",
            "obj/App.g.cs",
            "Views/Page.g.i.cs",
            "Api.generated.cs",
            "Data/DbContextModelSnapshot.cs",
        ] {
            assert!(is_generated(Path::new(generated)), "{generated}");
        }
        for written in ["Signer.cs", "Designer.cs", "Keys.java"] {
            assert!(!is_generated(Path::new(written)), "{written}");
        }
    }

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
