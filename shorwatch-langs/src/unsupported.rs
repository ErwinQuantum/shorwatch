//! Source languages Shorwatch recognises by extension but has no frontend for.
//!
//! A scan skips these files, and a report that said only "0 findings" would
//! read as "clean" when nothing was looked at. Counting them lets the report
//! say what it did not analyze.

use std::path::Path;

/// `(language, extensions)` of the languages that commonly hold cryptography.
const UNSUPPORTED: &[(&str, &[&str])] = &[
    ("Python", &["py"]),
    ("Go", &["go"]),
    ("JavaScript", &["js", "mjs", "cjs", "jsx"]),
    ("TypeScript", &["ts", "mts", "cts", "tsx"]),
    ("Ruby", &["rb"]),
    ("PHP", &["php"]),
    ("Rust", &["rs"]),
    ("C/C++", &["c", "h", "cc", "cpp", "cxx", "hpp"]),
    ("Swift", &["swift"]),
    ("Objective-C", &["m", "mm"]),
    ("Scala", &["scala"]),
    ("Groovy", &["groovy"]),
    ("Dart", &["dart"]),
    ("F#", &["fs"]),
    ("Visual Basic", &["vb"]),
];

/// The language of a source file no frontend handles, if it is one we know of.
pub fn unsupported_language(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?;
    UNSUPPORTED
        .iter()
        .find(|(_, extensions)| {
            extensions
                .iter()
                .any(|known| known.eq_ignore_ascii_case(extension))
        })
        .map(|(language, _)| *language)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_languages_are_named_by_extension() {
        assert_eq!(
            unsupported_language(Path::new("app/main.py")),
            Some("Python")
        );
        assert_eq!(
            unsupported_language(Path::new("web/App.TSX")),
            Some("TypeScript")
        );
        assert_eq!(unsupported_language(Path::new("src/lib.rs")), Some("Rust"));
    }

    #[test]
    fn supported_and_unknown_files_are_not_listed() {
        for path in [
            "A.java",
            "A.cs",
            "pom.xml",
            "README.md",
            "Makefile",
            "image.png",
        ] {
            assert_eq!(unsupported_language(Path::new(path)), None, "{path}");
        }
    }
}
