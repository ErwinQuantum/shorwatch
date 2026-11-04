//! A Gradle version catalog (`gradle/libs.versions.toml`): the libraries a
//! project names once and uses by alias.
//!
//! Only the shapes catalogs use are read: `[versions]` with plain or
//! `{ strictly = ".." }` values, and `[libraries]` entries that are a
//! `"group:artifact:version"` string or an inline table with `module` (or
//! `group` and `name`) and a `version` (a string, or `version.ref` to one of
//! `[versions]`). Inline tables must sit on one line in TOML, so a line is the
//! unit; nothing else of TOML is needed.

use std::collections::HashMap;

use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, SourceUnit};

use crate::span::Lines;
use crate::{Frontend, LangError};

#[derive(Debug, Clone, Copy, Default)]
pub struct VersionCatalogFrontend;

impl Frontend for VersionCatalogFrontend {
    fn language(&self) -> Language {
        Language::VersionCatalog
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    fn file_names(&self) -> &'static [&'static str] {
        &["libs.versions.toml"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let lines = Lines::new(source);
        let mut unit = SourceUnit::new(path, Language::VersionCatalog);
        let mut versions: HashMap<String, String> = HashMap::new();
        let mut libraries = Vec::new();
        let mut section = String::new();
        let mut offset = 0;
        for line in source.split_inclusive('\n') {
            let start = offset;
            offset += line.len();
            let text = without_comment(line).trim();
            if let Some(header) = text.strip_prefix('[') {
                header.trim_end_matches(']').trim().clone_into(&mut section);
                continue;
            }
            let Some((key, value)) = text.split_once('=') else {
                continue;
            };
            let key = key.trim().trim_matches(['"', '\'']);
            let value = parse_value(value.trim());
            match (section.as_str(), value) {
                ("versions", Some(value)) => {
                    if let Some(version) = value.version() {
                        versions.insert(key.to_owned(), version);
                    }
                }
                ("libraries", Some(value)) => {
                    let end = start + line.trim_end().len();
                    libraries.push((value, start, end));
                }
                _ => {}
            }
        }
        for (value, start, end) in libraries {
            let Some((group, artifact, version)) = value.library(&versions) else {
                continue;
            };
            unit.push(
                FactKind::Dependency {
                    group,
                    artifact,
                    version,
                    scope: None,
                },
                SourceUnit::ROOT,
                lines.range(start, end),
            );
        }
        Ok(unit)
    }
}

/// The line without a `#` comment (a `#` inside a string stays).
fn without_comment(line: &str) -> &str {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '#') => return &line[..i],
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
    }
    line
}

/// What a value of the catalog is: a string, or an inline table whose keys
/// are flattened (`version.ref`).
#[derive(Debug)]
enum Value {
    Str(String),
    Table(Vec<(String, String)>),
}

impl Value {
    fn field(&self, key: &str) -> Option<&str> {
        match self {
            Value::Table(pairs) => pairs
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str()),
            Value::Str(_) => None,
        }
    }

    /// A `[versions]` value: `"1.0"` or `{ strictly = "1.0" }`
    /// (`require`, `prefer`).
    fn version(&self) -> Option<String> {
        match self {
            Value::Str(version) => Some(version.clone()),
            Value::Table(_) => ["strictly", "require", "prefer"]
                .iter()
                .find_map(|k| self.field(k))
                .map(str::to_owned),
        }
    }

    /// A `[libraries]` value as coordinates, its `version.ref` resolved.
    fn library(
        &self,
        versions: &HashMap<String, String>,
    ) -> Option<(String, String, Option<String>)> {
        if let Value::Str(notation) = self {
            let mut parts = notation.split(':');
            let (group, artifact) = (parts.next()?, parts.next()?);
            return Some((
                group.to_owned(),
                artifact.to_owned(),
                parts.next().map(str::to_owned),
            ));
        }
        let (group, artifact) = match self.field("module") {
            Some(module) => {
                let (group, artifact) = module.split_once(':')?;
                (group, artifact)
            }
            None => (self.field("group")?, self.field("name")?),
        };
        let version = self
            .field("version")
            .map(str::to_owned)
            .or_else(|| versions.get(self.field("version.ref")?).cloned())
            .or_else(|| {
                ["version.strictly", "version.require", "version.prefer"]
                    .iter()
                    .find_map(|k| self.field(k))
                    .map(str::to_owned)
            });
        Some((group.to_owned(), artifact.to_owned(), version))
    }
}

fn parse_value(text: &str) -> Option<Value> {
    if let Some((value, _)) = string(text) {
        return Some(Value::Str(value));
    }
    let body = text.strip_prefix('{')?;
    let mut pairs = Vec::new();
    table(body, "", 0, &mut pairs)?;
    Some(Value::Table(pairs))
}

/// Catalogs nest a table once (`version = { ref = ".." }`).
const MAX_NESTING: usize = 4;

/// The quoted string at the start of `text`, and what follows it.
fn string(text: &str) -> Option<(String, &str)> {
    let quote = text.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let body = &text[1..];
    let end = body.find(quote)?;
    Some((body[..end].to_owned(), &body[end + 1..]))
}

/// The `key = value` pairs of an inline table's body, up to its closing `}`;
/// returns what follows it. Nested tables flatten their keys with a dot.
fn table<'a>(
    body: &'a str,
    prefix: &str,
    depth: usize,
    pairs: &mut Vec<(String, String)>,
) -> Option<&'a str> {
    if depth > MAX_NESTING {
        return None;
    }
    let mut rest = body;
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        if let Some(after) = rest.strip_prefix('}') {
            return Some(after);
        }
        let (key, after) = rest.split_once('=')?;
        let key = key.trim().trim_matches(['"', '\'']);
        let key = if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        };
        let value = after.trim_start();
        if let Some((text, after)) = string(value) {
            pairs.push((key, text));
            rest = after;
        } else if let Some(inner) = value.strip_prefix('{') {
            rest = table(inner, &key, depth + 1, pairs)?;
        } else {
            // A boolean or a number: not a coordinate, skipped to the next comma.
            rest = value.split_once(',').map_or("}", |(_, after)| after);
        }
    }
}
