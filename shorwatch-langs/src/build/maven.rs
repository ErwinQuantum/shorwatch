//! Maven `pom.xml`: the dependencies a project declares.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::Event;
use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, SourceUnit};

use crate::span::Lines;
use crate::{Frontend, LangError};

/// A POM nests a handful of levels; more is a file built to be hard to read.
const MAX_DEPTH: usize = 100;

/// No group, artifact or version is longer than this once resolved.
const MAX_COORDINATE: usize = 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct MavenFrontend;

impl Frontend for MavenFrontend {
    fn language(&self) -> Language {
        Language::Maven
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    fn file_names(&self) -> &'static [&'static str] {
        &["pom.xml"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let pom = read(path, source)?;
        let lines = Lines::new(source);
        let mut unit = SourceUnit::new(path, Language::Maven);
        for raw in pom.dependencies {
            let (Some(group), Some(artifact)) = (
                raw.group.and_then(|g| resolve(&g, &pom.properties)),
                raw.artifact.and_then(|a| resolve(&a, &pom.properties)),
            ) else {
                continue;
            };
            let version = raw.version.and_then(|v| resolve(&v, &pom.properties));
            let scope = match (raw.scope, raw.managed) {
                (Some(scope), _) => Some(scope),
                (None, true) => Some("managed".to_owned()),
                (None, false) => None,
            };
            unit.push(
                FactKind::Dependency {
                    group,
                    artifact,
                    version,
                    scope,
                },
                SourceUnit::ROOT,
                lines.range(raw.start, raw.end),
            );
        }
        Ok(unit)
    }
}

#[derive(Default)]
struct Pom {
    dependencies: Vec<RawDependency>,
    /// `<properties>` plus the project's own coordinates, by the names
    /// `${...}` uses.
    properties: HashMap<String, String>,
}

#[derive(Default)]
struct RawDependency {
    /// The byte range of its start tag.
    start: usize,
    end: usize,
    group: Option<String>,
    artifact: Option<String>,
    version: Option<String>,
    scope: Option<String>,
    managed: bool,
}

/// Walks the events once, with an explicit stack of element names (no
/// recursion, however the file nests).
fn read(path: &str, source: &str) -> Result<Pom, LangError> {
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(true);
    let mut pom = Pom::default();
    let mut stack: Vec<String> = Vec::new();
    let mut current: Option<RawDependency> = None;
    let mut text = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                let end = position(&reader);
                stack.push(tag.local_name().into_inner().to_owned());
                if stack.len() > MAX_DEPTH {
                    return Err(LangError::TooDeep(path.to_owned(), MAX_DEPTH));
                }
                text.clear();
                if declares_dependency(&stack) {
                    current = Some(RawDependency {
                        // `<` and `>` around the tag's own bytes.
                        start: end.saturating_sub(tag.len() + 2),
                        end,
                        managed: stack.iter().any(|n| n == "dependencyManagement"),
                        ..RawDependency::default()
                    });
                }
            }
            Ok(Event::End(_)) => {
                let Some(name) = stack.pop() else {
                    return Err(LangError::Parse(path.to_owned()));
                };
                let value = text.trim().to_owned();
                text.clear();
                if name == "dependency" {
                    pom.dependencies.extend(current.take());
                } else if let Some(dependency) = current
                    .as_mut()
                    .filter(|_| stack.last().is_some_and(|p| p == "dependency"))
                {
                    match name.as_str() {
                        "groupId" => dependency.group = Some(value),
                        "artifactId" => dependency.artifact = Some(value),
                        "version" => dependency.version = Some(value),
                        "scope" => dependency.scope = Some(value),
                        _ => {}
                    }
                } else {
                    define(&mut pom.properties, &stack, &name, value);
                }
            }
            Ok(Event::Text(t)) => text.push_str(&t.xml10_content()),
            Ok(Event::CData(t)) => text.push_str(&t.xml10_content()),
            Ok(Event::GeneralRef(r)) => text.push_str(&entity(&r.into_inner())),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(LangError::Parse(path.to_owned())),
        }
    }
    Ok(pom)
}

fn position(reader: &Reader<&[u8]>) -> usize {
    usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX)
}

/// `<dependency>` of a `<dependencies>` list, not one a plugin or a report
/// uses for itself.
fn declares_dependency(stack: &[String]) -> bool {
    let [.., parent, name] = stack else {
        return false;
    };
    name == "dependency"
        && parent == "dependencies"
        && !stack
            .iter()
            .any(|n| matches!(n.as_str(), "plugin" | "plugins" | "reporting" | "extension"))
}

/// Records what `${name}` can refer to: `<properties>`, and the project's own
/// version and group (`${project.version}`, `${revision}` is a property).
fn define(properties: &mut HashMap<String, String>, stack: &[String], name: &str, value: String) {
    let path: Vec<&str> = stack.iter().map(String::as_str).collect();
    match path.as_slice() {
        ["project", "properties"] => {
            properties.insert(name.to_owned(), value);
        }
        ["project"] if name == "version" || name == "groupId" => {
            properties.insert(format!("project.{name}"), value.clone());
            properties.insert(format!("pom.{name}"), value.clone());
            properties.insert(name.to_owned(), value);
        }
        ["project", "parent"] if name == "version" || name == "groupId" => {
            properties.insert(format!("project.parent.{name}"), value.clone());
            // The project inherits them when it does not set its own.
            properties
                .entry(format!("project.{name}"))
                .or_insert_with(|| value.clone());
            properties.entry(format!("pom.{name}")).or_insert(value);
        }
        _ => {}
    }
}

/// The predefined XML entities; anything else is dropped.
fn entity(name: &str) -> String {
    match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        _ => "",
    }
    .to_owned()
}

/// `value` with its `${property}` references replaced; `None` when one is
/// left (defined in a parent POM or the build, so the file does not say).
fn resolve(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    let mut value = value.to_owned();
    // A property may refer to another; a loop between them ends here. A
    // property that refers to itself twice doubles the text each time, so
    // what a coordinate could be is bounded too.
    for _ in 0..8 {
        let Some(open) = value.find("${") else {
            return (!value.is_empty()).then_some(value);
        };
        let close = value[open..].find('}')? + open;
        let replacement = properties.get(&value[open + 2..close])?;
        value.replace_range(open..=close, replacement);
        if value.len() > MAX_COORDINATE {
            return None;
        }
    }
    None
}
