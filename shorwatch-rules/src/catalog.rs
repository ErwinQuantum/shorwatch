//! Collecting rule files and assembling them into [`Rule`]s: profiles and
//! marker sets are merged into the rules that reference them.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml_ng::{Mapping, Value};
use shorwatch_core::{LibrarySpec, Rule};

use crate::LoadError;

/// Built-in rule files, keyed by their path under `rules/` (see `build.rs`).
const BUILTIN: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/builtin.rs"));

#[derive(Debug, Clone)]
pub(crate) struct Source {
    /// Where the file came from, for error messages (`builtin:<path>` for
    /// the embedded rules).
    pub(crate) origin: String,
    pub(crate) doc: Mapping,
}

/// Rule files collected from one or more rules directories, before assembly.
#[derive(Debug, Default, Clone)]
pub struct Catalog {
    pub(crate) profiles: BTreeMap<String, Source>,
    pub(crate) markers: BTreeMap<String, Source>,
    pub(crate) rules: Vec<Source>,
    /// `libraries/<id>.yaml`: the known cryptographic libraries, which are
    /// not rules (they feed the dependency inventory).
    pub(crate) libraries: Vec<Source>,
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
            Some("libraries") => {
                self.libraries.push(source);
                return Ok(());
            }
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

    /// Every known library.
    pub fn libraries(&self) -> Result<Vec<LibrarySpec>, LoadError> {
        self.libraries.iter().map(library).collect()
    }

    pub(crate) fn assemble(&self, rule: &Source) -> Result<Rule, LoadError> {
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
pub(crate) fn deserialize(origin: &str, value: Value) -> Result<Rule, LoadError> {
    serde_yaml_ng::with::singleton_map_recursive::deserialize(value).map_err(|e| LoadError::Parse {
        origin: origin.to_owned(),
        message: e.to_string(),
    })
}

fn library(source: &Source) -> Result<LibrarySpec, LoadError> {
    serde_yaml_ng::from_value(Value::Mapping(source.doc.clone())).map_err(|e| LoadError::Parse {
        origin: source.origin.clone(),
        message: e.to_string(),
    })
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
