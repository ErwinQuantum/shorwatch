//! Embeds every file under `rules/` into the binary, so adding a rule is just
//! adding a file.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    println!("cargo:rerun-if-changed={}", root.display());

    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();

    let mut out = String::from("&[\n");
    for file in &files {
        let relative = file.strip_prefix(&root).unwrap();
        let name = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        writeln!(out, "    ({name:?}, include_str!({:?})),", file.display()).unwrap();
    }
    out.push(']');

    let dest = PathBuf::from(env::var("OUT_DIR").unwrap()).join("builtin.rs");
    fs::write(dest, out).unwrap();
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(path);
        }
    }
}
