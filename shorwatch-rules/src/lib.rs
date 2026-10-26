//! # shorwatch-rules
//!
//! Detection rules are data. This crate ships the built-in YAML rules
//! (embedded at compile time) and loads additional rule files from disk, so a
//! new detection never requires touching or recompiling the engine.
//!
//! A rules directory has three kinds of files, told apart by their location:
//!
//! - `algorithms/<profile>.yaml`: what an algorithm is and why it matters
//!   (category, severity, message, migration advice, references, hybrid
//!   markers). Written once per algorithm.
//! - `markers/<name>.yaml`: a named set of hybrid markers, referenced from
//!   profiles as `hybrid: <name>`.
//! - anything else, e.g. `jvm/nimbus/jose-rsa.yaml`: a rule, i.e. the patterns
//!   one library exposes, plus `profile: <profile>`. Its fields override the
//!   profile's, and a rule may also be fully self-contained.
//!
//! Schema validation happens in two layers: the assembled YAML must
//! deserialize into [`Rule`] (unknown fields are rejected), and the resulting
//! rules must pass [`RuleSet::compile`], which enforces the domain invariants.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml_ng::{Mapping, Value};
pub use shorwatch_core::{Rule, RuleError, RuleSet};
use thiserror::Error;

/// Built-in rule files, keyed by their path under `rules/` (see `build.rs`).
const BUILTIN: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/builtin.rs"));

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("{origin}: {message}")]
    Parse { origin: String, message: String },
    #[error("{origin}: unknown profile `{profile}`")]
    UnknownProfile { origin: String, profile: String },
    #[error("{origin}: unknown marker set `{markers}`")]
    UnknownMarkers { origin: String, markers: String },
    #[error("{origin}: `{name}` is already defined by {previous}")]
    Duplicate {
        origin: String,
        name: String,
        previous: String,
    },
    #[error("failed to read `{}`: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Invalid(#[from] RuleError),
}

#[derive(Debug, Clone)]
struct Source {
    /// Where the file came from, for error messages (`builtin:<path>` for
    /// the embedded rules).
    origin: String,
    doc: Mapping,
}

/// Rule files collected from one or more rules directories, before assembly.
#[derive(Debug, Default, Clone)]
pub struct Catalog {
    profiles: BTreeMap<String, Source>,
    markers: BTreeMap<String, Source>,
    rules: Vec<Source>,
}

impl Catalog {
    /// The files shipped with Shorwatch.
    pub fn builtin() -> Result<Self, LoadError> {
        let mut catalog = Self::default();
        for (path, yaml) in BUILTIN {
            catalog.add(path, &format!("builtin:{path}"), yaml)?;
        }
        Ok(catalog)
    }

    /// Adds one file. `path` is relative to its rules root and decides what
    /// the file is; `origin` names it in error messages.
    pub fn add(&mut self, path: &str, origin: &str, yaml: &str) -> Result<(), LoadError> {
        let doc: Mapping = serde_yaml_ng::from_str(yaml).map_err(|e| LoadError::Parse {
            origin: origin.to_owned(),
            message: e.to_string(),
        })?;
        let source = Source {
            origin: origin.to_owned(),
            doc,
        };
        let stem = || {
            let file = path.rsplit('/').next().unwrap_or(path);
            file.rsplit_once('.').map_or(file, |(s, _)| s).to_owned()
        };
        let table = match path.split('/').next() {
            Some("algorithms") => &mut self.profiles,
            Some("markers") => &mut self.markers,
            _ => {
                self.rules.push(source);
                return Ok(());
            }
        };
        let name = stem();
        if let Some(previous) = table.get(&name) {
            return Err(LoadError::Duplicate {
                origin: origin.to_owned(),
                name,
                previous: previous.origin.clone(),
            });
        }
        table.insert(name, source);
        Ok(())
    }

    /// Adds every `*.yaml` / `*.yml` file under `dir`, recursively, in path order.
    pub fn add_dir(&mut self, dir: &Path) -> Result<(), LoadError> {
        let mut files = Vec::new();
        collect_rule_files(dir, &mut files)?;
        files.sort();
        for file in files {
            let yaml = fs::read_to_string(&file).map_err(|source| LoadError::Io {
                path: file.clone(),
                source,
            })?;
            let relative = file.strip_prefix(dir).unwrap_or(&file);
            let path = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            self.add(&path, &file.display().to_string(), &yaml)?;
        }
        Ok(())
    }

    /// Every rule, assembled with its profile and markers.
    pub fn rules(&self) -> Result<Vec<Rule>, LoadError> {
        self.rules.iter().map(|r| self.assemble(r)).collect()
    }

    fn assemble(&self, rule: &Source) -> Result<Rule, LoadError> {
        let mut doc = rule.doc.clone();
        if let Some(profile) = doc.remove("profile") {
            let name = profile.as_str().unwrap_or_default();
            let profile = self
                .profiles
                .get(name)
                .ok_or_else(|| LoadError::UnknownProfile {
                    origin: rule.origin.clone(),
                    profile: name.to_owned(),
                })?;
            for (key, value) in &profile.doc {
                if !doc.contains_key(key) {
                    doc.insert(key.clone(), value.clone());
                }
            }
        }
        if let Some(Value::String(name)) = doc.get("hybrid") {
            let markers = self
                .markers
                .get(name)
                .ok_or_else(|| LoadError::UnknownMarkers {
                    origin: rule.origin.clone(),
                    markers: name.clone(),
                })?;
            doc.insert("hybrid".into(), Value::Mapping(markers.doc.clone()));
        }
        deserialize(&rule.origin, Value::Mapping(doc))
    }
}

/// `singleton_map_recursive` lets enums be written as `- call: {...}` instead
/// of YAML tags (`- !call {...}`), keeping rule files plain.
fn deserialize(origin: &str, value: Value) -> Result<Rule, LoadError> {
    serde_yaml_ng::with::singleton_map_recursive::deserialize(value).map_err(|e| LoadError::Parse {
        origin: origin.to_owned(),
        message: e.to_string(),
    })
}

/// Parses one self-contained rule (no profile). `origin` names the source in
/// error messages.
pub fn parse(origin: &str, yaml: &str) -> Result<Rule, LoadError> {
    let value: Value = serde_yaml_ng::from_str(yaml).map_err(|e| LoadError::Parse {
        origin: origin.to_owned(),
        message: e.to_string(),
    })?;
    deserialize(origin, value)
}

/// The rules shipped with Shorwatch.
pub fn builtin_rules() -> Result<Vec<Rule>, LoadError> {
    Catalog::builtin()?.rules()
}

/// The built-in rules, compiled.
pub fn builtin() -> Result<RuleSet, LoadError> {
    Ok(RuleSet::compile(builtin_rules()?)?)
}

/// The rules under `dir`. They may use the built-in profiles and markers as
/// well as their own.
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, LoadError> {
    let mut catalog = Catalog::builtin()?;
    let builtin = catalog.rules.len();
    catalog.add_dir(dir)?;
    catalog.rules[builtin..]
        .iter()
        .map(|r| catalog.assemble(r))
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const MINIMAL: &str = r#"
id: test.rule
platform: jvm
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

    const PROFILE: &str = r#"
algorithm: X
category: shor
severity: high
title: t
message: m
suggestion: s
references: [{ title: r, url: "https://example.com" }]
hybrid: pqc
"#;

    const MARKERS: &str = "scope: type\nmarkers:\n  - literal: 'ml-kem'\n";

    fn catalog(files: &[(&str, &str)]) -> Catalog {
        let mut catalog = Catalog::default();
        for (path, yaml) in files {
            catalog.add(path, path, yaml).unwrap();
        }
        catalog
    }

    #[test]
    fn builtin_rules_compile() {
        assert!(!builtin().unwrap().is_empty());
    }

    #[test]
    fn rules_inherit_their_profile_and_markers() {
        let rule = "id: jvm.lib.x\nprofile: x\nplatform: jvm\npatterns:\n  - call: { type: a.B, method: c }\n";
        let catalog = catalog(&[
            ("algorithms/x.yaml", PROFILE),
            ("markers/pqc.yaml", MARKERS),
            ("jvm/lib/x.yaml", rule),
        ]);
        let rules = catalog.rules().unwrap();
        assert_eq!(rules[0].algorithm, "X");
        assert_eq!(rules[0].hybrid.as_ref().unwrap().markers.len(), 1);
    }

    #[test]
    fn rule_fields_override_the_profile() {
        let rule = "id: r\nprofile: x\nplatform: jvm\nseverity: low\npatterns:\n  - call: { type: a.B, method: c }\n";
        let catalog = catalog(&[
            ("algorithms/x.yaml", PROFILE),
            ("markers/pqc.yaml", MARKERS),
            ("jvm/r.yaml", rule),
        ]);
        assert_eq!(
            catalog.rules().unwrap()[0].severity,
            shorwatch_core::Severity::Low
        );
    }

    #[test]
    fn unknown_profile_is_an_error() {
        let rule = "id: r\nprofile: nope\nplatform: jvm\npatterns: []\n";
        let err = catalog(&[("jvm/r.yaml", rule)]).rules().unwrap_err();
        assert!(matches!(err, LoadError::UnknownProfile { profile, .. } if profile == "nope"));
    }

    #[test]
    fn duplicate_profiles_are_rejected() {
        let mut catalog = catalog(&[("algorithms/x.yaml", PROFILE)]);
        let err = catalog
            .add("algorithms/x.yaml", "other", PROFILE)
            .unwrap_err();
        assert!(matches!(err, LoadError::Duplicate { name, .. } if name == "x"));
    }

    /// `jvm/nimbus/jose-rsa.yaml` must be `jvm.nimbus.jose-rsa`, target the
    /// `jvm` platform and use the `jose-rsa` profile: the tree is the index.
    #[test]
    fn builtin_rules_follow_the_layout_convention() {
        let catalog = Catalog::builtin().unwrap();
        for source in &catalog.rules {
            let path = source.origin.strip_prefix("builtin:").unwrap();
            let path = path.trim_end_matches(".yaml");
            let get = |key: &str| source.doc.get(key).and_then(Value::as_str);
            assert_eq!(get("id"), Some(path.replace('/', ".").as_str()), "{path}");
            assert_eq!(get("platform"), path.split('/').next(), "{path}");
            assert_eq!(get("profile"), path.rsplit('/').next(), "{path}");
        }
    }

    #[test]
    fn every_builtin_profile_and_marker_set_is_used() {
        let catalog = Catalog::builtin().unwrap();
        let used: BTreeSet<_> = catalog
            .rules
            .iter()
            .filter_map(|r| r.doc.get("profile").and_then(Value::as_str))
            .collect();
        let unused: Vec<_> = catalog
            .profiles
            .keys()
            .filter(|p| !used.contains(p.as_str()))
            .collect();
        assert!(unused.is_empty(), "unused profiles: {unused:?}");

        let used_markers: BTreeSet<_> = catalog
            .profiles
            .values()
            .filter_map(|p| p.doc.get("hybrid").and_then(Value::as_str))
            .collect();
        for name in catalog.markers.keys() {
            assert!(
                used_markers.contains(name.as_str()),
                "unused markers: {name}"
            );
        }
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
    fn parses_field_and_property_patterns() {
        let yaml = MINIMAL.replace(
            "  - call: { type: a.B, method: c }",
            "  - field: { type: a.B, matches: '^RS' }\n  - field: { type: a.C }\n  - property: { key: '^jwt\\.alg$', matches: '^RS' }",
        );
        let rule = parse("test", &yaml).unwrap();
        assert_eq!(rule.patterns.len(), 3);
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
