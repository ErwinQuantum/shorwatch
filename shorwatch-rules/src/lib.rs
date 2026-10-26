//! # shorwatch-rules
//!
//! Detection rules are data. This crate ships the built-in YAML rules
//! (embedded at compile time) and loads additional rule files from disk, so a
//! new detection never requires touching or recompiling the engine.
//!
//! Schema validation happens in two layers: the YAML must deserialize into
//! [`Rule`] (unknown fields are rejected), and the resulting rules must pass
//! [`RuleSet::compile`], which enforces the domain invariants.

use std::fs;
use std::path::{Path, PathBuf};

pub use shorwatch_core::{Rule, RuleError, RuleSet};
use thiserror::Error;

macro_rules! builtin {
    ($($file:literal),* $(,)?) => {
        &[$(($file, include_str!(concat!("../rules/", $file)))),*]
    };
}

/// Built-in rule files, keyed by their path under `rules/`.
const BUILTIN: &[(&str, &str)] = builtin![
    "java/rsa.yaml",
    "java/dh.yaml",
    "java/ecdh.yaml",
    "java/ecdsa.yaml",
    "java/ec.yaml",
    "java/eddsa.yaml",
    "java/dsa.yaml",
    "java/elgamal.yaml",
    "java/aes-128.yaml",
    "java/sha1.yaml",
    "java/3des.yaml",
    "java/jwt-rsa.yaml",
    "java/jwt-ecdsa.yaml",
    "java/jwt-eddsa.yaml",
    "java/jwt-ecdh.yaml",
];

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("{origin}: {message}")]
    Parse { origin: String, message: String },
    #[error("failed to read `{}`: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Invalid(#[from] RuleError),
}

/// Parses one rule. `origin` names the source in error messages.
pub fn parse(origin: &str, yaml: &str) -> Result<Rule, LoadError> {
    // `singleton_map_recursive` lets enums be written as `- call: {...}`
    // instead of YAML tags (`- !call {...}`), keeping rule files plain.
    let deserializer = serde_yaml_ng::Deserializer::from_str(yaml);
    serde_yaml_ng::with::singleton_map_recursive::deserialize(deserializer).map_err(|e| {
        LoadError::Parse {
            origin: origin.to_owned(),
            message: e.to_string(),
        }
    })
}

/// The rules shipped with Shorwatch.
pub fn builtin_rules() -> Result<Vec<Rule>, LoadError> {
    BUILTIN
        .iter()
        .map(|(name, yaml)| parse(&format!("builtin:{name}"), yaml))
        .collect()
}

/// Every `*.yaml` / `*.yml` file under `dir`, recursively, in path order.
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, LoadError> {
    let mut files = Vec::new();
    collect_rule_files(dir, &mut files)?;
    files.sort();
    files
        .iter()
        .map(|path| {
            let yaml = fs::read_to_string(path).map_err(|source| LoadError::Io {
                path: path.clone(),
                source,
            })?;
            parse(&path.display().to_string(), &yaml)
        })
        .collect()
}

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    let io = |source| LoadError::Io {
        path: dir.to_owned(),
        source,
    };
    for entry in fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        if path.is_dir() {
            collect_rule_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(path);
        }
    }
    Ok(())
}

/// The built-in rules, compiled.
pub fn builtin() -> Result<RuleSet, LoadError> {
    Ok(RuleSet::compile(builtin_rules()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
id: test.rule
language: java
algorithm: X
category: shor
severity: low
title: t
message: m
suggestion: s
references: [{ title: r, url: "https://example.com" }]
patterns:
  - call: { type: a.B, method: c }
"#;

    #[test]
    fn builtin_rules_compile() {
        let set = builtin().unwrap();
        assert_eq!(set.len(), BUILTIN.len());
    }

    #[test]
    fn every_rule_file_is_registered_as_builtin() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
        let on_disk = load_dir(&dir).unwrap();
        let mut on_disk: Vec<_> = on_disk.into_iter().map(|r| r.id).collect();
        let mut builtin: Vec<_> = builtin_rules().unwrap().into_iter().map(|r| r.id).collect();
        on_disk.sort();
        builtin.sort();
        assert_eq!(builtin, on_disk, "add new rule files to `BUILTIN`");
    }

    #[test]
    fn shor_rules_point_to_a_pqc_standard() {
        for rule in builtin_rules().unwrap() {
            if rule.category == shorwatch_core::Category::Shor {
                assert!(
                    rule.references
                        .iter()
                        .any(|r| r.url.contains("/fips/203/") || r.url.contains("/fips/204/")),
                    "{} must reference FIPS 203 or FIPS 204",
                    rule.id
                );
            }
        }
    }

    #[test]
    fn parses_a_minimal_rule() {
        let rule = parse("test", MINIMAL).unwrap();
        assert_eq!(rule.id, "test.rule");
        assert!(rule.hybrid.is_none());
    }

    #[test]
    fn parses_field_patterns() {
        let yaml = MINIMAL.replace(
            "  - call: { type: a.B, method: c }",
            "  - field: { type: a.B, matches: '^RS' }\n  - field: { type: a.C }",
        );
        let rule = parse("test", &yaml).unwrap();
        assert_eq!(rule.patterns.len(), 2);
        assert!(RuleSet::compile([rule]).is_ok());
    }

    #[test]
    fn rejects_unknown_fields() {
        let yaml = format!("{MINIMAL}autofix: true\n");
        let err = parse("test", &yaml).unwrap_err();
        assert!(err.to_string().contains("autofix"), "{err}");
    }

    #[test]
    fn rejects_fix_on_shor_rule() {
        let yaml = format!("{MINIMAL}fix: {{ description: d, replace: a, with: b }}\n");
        let rule = parse("test", &yaml).unwrap();
        assert!(matches!(
            RuleSet::compile([rule]),
            Err(RuleError::FixNotAllowed(id)) if id == "test.rule"
        ));
    }

    #[test]
    fn error_names_the_origin() {
        let err = parse("rules/broken.yaml", "id: [").unwrap_err();
        assert!(err.to_string().starts_with("rules/broken.yaml:"), "{err}");
    }
}
