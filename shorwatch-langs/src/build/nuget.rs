//! NuGet package lists: the packages a .NET project declares.
//!
//! Three files hold them, all XML:
//! - an SDK-style project (`*.csproj`, `*.fsproj`, `*.vbproj`) and
//!   `Directory.Build.props`: `<PackageReference Include=".." Version=".." />`;
//! - `Directory.Packages.props` (central package management): the versions of
//!   every project, as `<PackageVersion Include=".." Version=".." />`, which
//!   are reported with the scope `managed`, like a Maven BOM;
//! - `packages.config` (the older format): `<package id=".." version=".." />`.
//!
//! A version written as `$(Property)` is resolved from the file's own
//! `<PropertyGroup>`; whatever else the build computes is left out.

use std::collections::HashMap;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, SourceUnit};

use crate::span::Lines;
use crate::{Frontend, LangError};

/// A project file nests a handful of levels; more is a file built to be hard
/// to read.
const MAX_DEPTH: usize = 100;

/// No id or version is longer than this once resolved.
const MAX_COORDINATE: usize = 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct NuGetFrontend;

impl Frontend for NuGetFrontend {
    fn language(&self) -> Language {
        Language::NuGet
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["csproj", "fsproj", "vbproj"]
    }

    fn file_names(&self) -> &'static [&'static str] {
        &[
            "packages.config",
            "Directory.Packages.props",
            "Directory.Build.props",
        ]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let file = read(path, source)?;
        let lines = Lines::new(source);
        let mut unit = SourceUnit::new(path, Language::NuGet);
        for raw in file.packages {
            let Some(id) = resolve(&raw.id, &file.properties) else {
                continue;
            };
            let version = raw
                .version
                .and_then(|v| resolve(&v, &file.properties))
                .map(exact);
            unit.push(
                FactKind::Dependency {
                    group: String::new(),
                    artifact: id,
                    version,
                    scope: raw.scope.map(str::to_owned),
                },
                SourceUnit::ROOT,
                lines.range(raw.start, raw.end),
            );
        }
        Ok(unit)
    }
}

#[derive(Default)]
struct ProjectFile {
    packages: Vec<RawPackage>,
    /// `<PropertyGroup>` entries, by the names `$(...)` uses.
    properties: HashMap<String, String>,
}

struct RawPackage {
    /// The byte range of its tag (or of its start tag, when it has children).
    start: usize,
    end: usize,
    id: String,
    version: Option<String>,
    scope: Option<&'static str>,
}

/// Walks the events once, with an explicit stack of element names (no
/// recursion, however the file nests).
fn read(path: &str, source: &str) -> Result<ProjectFile, LangError> {
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(true);
    let mut file = ProjectFile::default();
    let mut stack: Vec<String> = Vec::new();
    // A `<PackageReference>` that holds its `<Version>` as a child element.
    let mut open: Option<RawPackage> = None;
    let mut text = String::new();
    loop {
        let before = position(&reader);
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                let name = local_name(&tag);
                stack.push(name.clone());
                if stack.len() > MAX_DEPTH {
                    return Err(LangError::TooDeep(path.to_owned(), MAX_DEPTH));
                }
                text.clear();
                if let Some(package) = package(&tag, &name, before, position(&reader), source) {
                    open = Some(package);
                }
            }
            Ok(Event::Empty(tag)) => {
                let name = local_name(&tag);
                if let Some(package) = package(&tag, &name, before, position(&reader), source) {
                    file.packages.push(package);
                }
            }
            Ok(Event::End(_)) => {
                let Some(name) = stack.pop() else {
                    return Err(LangError::Parse(path.to_owned()));
                };
                let value = text.trim().to_owned();
                text.clear();
                if is_package_element(&name) {
                    file.packages.extend(open.take());
                } else if let Some(package) = open.as_mut().filter(|_| name == "Version") {
                    package.version = Some(value);
                } else if stack.last().is_some_and(|p| p == "PropertyGroup") && !value.is_empty() {
                    file.properties.insert(name, value);
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
    Ok(file)
}

fn position(reader: &Reader<&[u8]>) -> usize {
    usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX)
}

fn local_name(tag: &BytesStart<'_>) -> String {
    tag.local_name().into_inner().to_owned()
}

fn is_package_element(name: &str) -> bool {
    matches!(
        name,
        "PackageReference" | "PackageVersion" | "GlobalPackageReference" | "package"
    )
}

/// The package a tag declares: its id and version from attributes (the
/// version may follow as a child element instead).
fn package(
    tag: &BytesStart<'_>,
    name: &str,
    before: usize,
    after: usize,
    source: &str,
) -> Option<RawPackage> {
    let (id_attribute, version_attribute, scope) = match name {
        "PackageReference" => ("Include", "Version", None),
        "PackageVersion" => ("Include", "Version", Some("managed")),
        "GlobalPackageReference" => ("Include", "Version", Some("global")),
        "package" => ("id", "version", None),
        _ => return None,
    };
    let mut id = None;
    let mut version = None;
    let mut version_override = None;
    for attribute in tag.attributes().filter_map(Result::ok) {
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .ok()?
            .into_owned();
        let key = attribute.key.local_name().into_inner();
        if key == id_attribute {
            id = Some(value);
        } else if key == version_attribute {
            version = Some(value);
        } else if key == "VersionOverride" {
            version_override = Some(value);
        }
    }
    // The tag begins at the next `<` after the last event (whitespace
    // between tags is skipped, not part of one).
    let start = before + source.get(before..)?.find('<')?;
    Some(RawPackage {
        start,
        end: after,
        id: id?,
        version: version_override.or(version),
        scope,
    })
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

/// `[1.2.3]` is NuGet's way to say exactly 1.2.3 (a range has a comma).
fn exact(version: String) -> String {
    match version.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        Some(inner) if !inner.contains(',') => inner.trim().to_owned(),
        _ => version,
    }
}

/// `value` with its `$(Property)` references replaced; `None` when one is
/// left (set by the build, or by a file this one does not see).
fn resolve(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    let mut value = value.trim().to_owned();
    // A property may refer to another; a loop between them ends here. A
    // property that refers to itself twice doubles the text each time, so
    // what a coordinate could be is bounded too.
    for _ in 0..8 {
        let Some(open) = value.find("$(") else {
            return (!value.is_empty()).then_some(value);
        };
        let close = value[open..].find(')')? + open;
        let replacement = properties.get(&value[open + 2..close])?;
        value.replace_range(open..=close, replacement);
        if value.len() > MAX_COORDINATE {
            return None;
        }
    }
    None
}
