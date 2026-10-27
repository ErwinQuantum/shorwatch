//! `--classpath`: compiled dependencies, read for their declarations only.
//! Entries are directories (searched for class files, jars and jmods), jars
//! and jmods; `@file` reads the entries from a file, such as the output of
//! `mvn dependency:build-classpath -Dmdep.outputFile=cp.txt`.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rayon::prelude::*;
use shorwatch_core::Library;

/// The JVM caps a class file's tables at 65,535 entries: real ones stay far
/// below this.
const MAX_CLASS_BYTES: u64 = 16 * 1024 * 1024;

/// Every class of the classpath, read in parallel. Unreadable entries and
/// malformed classes are reported on stderr and skipped: a classpath only
/// adds types, it never makes a scan fail.
pub fn load(values: &[OsString]) -> Result<Library> {
    let mut files = Vec::new();
    for entry in entries(values)? {
        if entry.is_dir() {
            let walk = ignore::WalkBuilder::new(&entry)
                .standard_filters(false)
                .build();
            files.extend(
                walk.filter_map(Result::ok)
                    .map(ignore::DirEntry::into_path)
                    .filter(|p| kind(p).is_some()),
            );
        } else if entry.is_file() && kind(&entry).is_some() {
            files.push(entry);
        } else {
            eprintln!(
                "warning: classpath entry `{}` is not a directory, jar, jmod or class file",
                entry.display()
            );
        }
    }
    Ok(files
        .par_iter()
        .map(|path| match read(path) {
            Ok(library) => library,
            Err(error) => {
                eprintln!("warning: skipping `{}`: {error:#}", path.display());
                Library::default()
            }
        })
        .reduce(Library::default, |mut a, b| {
            a.extend(b);
            a
        }))
}

/// The paths of `--classpath` values, split like `CLASSPATH` (`;` on
/// Windows, `:` elsewhere), with `@file` expanded (one or more per line).
fn entries(values: &[OsString]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for value in values {
        match value.to_str().and_then(|v| v.strip_prefix('@')) {
            Some(file) => {
                let text = fs::read_to_string(file)
                    .with_context(|| format!("cannot read classpath file `{file}`"))?;
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    paths.extend(std::env::split_paths(line));
                }
            }
            None => paths.extend(std::env::split_paths(value)),
        }
    }
    Ok(paths)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Class,
    Archive,
}

fn kind(path: &Path) -> Option<Kind> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "class" => Some(Kind::Class),
        "jar" | "jmod" => Some(Kind::Archive),
        _ => None,
    }
}

fn read(path: &Path) -> Result<Library> {
    if kind(path) == Some(Kind::Class) {
        return Ok(shorwatch_langs::bytecode::read_class(&fs::read(path)?)?);
    }
    // A jmod is a zip after a 4-byte header, which the zip reader skips
    // like any data prepended to an archive.
    let mut archive = zip::ZipArchive::new(BufReader::new(File::open(path)?))?;
    let mut library = Library::default();
    let mut bytes = Vec::new();
    let mut malformed = 0;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        // Multi-release jars repeat classes under META-INF/versions.
        let wanted = entry
            .name()
            .is_ok_and(|name| name.ends_with(".class") && !name.starts_with("META-INF/"));
        if !wanted {
            continue;
        }
        // A class file over this size is no class file: a zip bomb, say.
        if entry.size() > MAX_CLASS_BYTES {
            malformed += 1;
            continue;
        }
        bytes.clear();
        (&mut entry).take(MAX_CLASS_BYTES).read_to_end(&mut bytes)?;
        match shorwatch_langs::bytecode::read_class(&bytes) {
            Ok(class) => library.extend(class),
            Err(_) => malformed += 1,
        }
    }
    if malformed > 0 {
        eprintln!(
            "warning: `{}`: {malformed} malformed class files skipped",
            path.display()
        );
    }
    Ok(library)
}
