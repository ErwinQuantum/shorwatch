//! Gradle build scripts, Groovy and Kotlin DSL: the dependencies a project
//! declares.
//!
//! The scripts are programs, so this reads what is written plainly: a
//! configuration (`implementation`, `testImplementation`...) followed by
//! `"group:artifact:version"` or `group:, name:, version:` arguments, and
//! versions held in same-file variables (`val bc = "1.70"`, `ext { }`).
//! Whatever a script computes is left out, and so are version-catalog
//! aliases (`libs.bcprov`): the catalog file lists those.

use std::collections::HashMap;

use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, SourceUnit};

use crate::span::Lines;
use crate::{Frontend, LangError};

#[derive(Debug, Clone, Copy, Default)]
pub struct GradleFrontend;

impl Frontend for GradleFrontend {
    fn language(&self) -> Language {
        Language::Gradle
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    fn file_names(&self) -> &'static [&'static str] {
        &["build.gradle", "build.gradle.kts"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let tokens = tokenize(source);
        let variables = variables(&tokens);
        let lines = Lines::new(source);
        let mut unit = SourceUnit::new(path, Language::Gradle);
        for declared in declarations(&tokens, &variables) {
            unit.push(
                FactKind::Dependency {
                    group: declared.group,
                    artifact: declared.artifact,
                    version: declared.version,
                    scope: Some(declared.configuration),
                },
                SourceUnit::ROOT,
                lines.range(declared.start, declared.end),
            );
        }
        Ok(unit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Ident(String),
    /// `interpolates`: a double-quoted string, where `$name` is a variable.
    Str {
        value: String,
        interpolates: bool,
    },
    Punct(char),
}

#[derive(Debug, Clone)]
struct Token {
    kind: Kind,
    start: usize,
    end: usize,
}

/// Identifiers, strings and punctuation with their byte ranges; comments and
/// white space are dropped. A string that is never closed ends at the line.
fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = source.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '/' && chars.peek().is_some_and(|&(_, n)| n == '/') {
            while chars.next_if(|&(_, n)| n != '\n').is_some() {}
            continue;
        }
        if c == '/' && chars.peek().is_some_and(|&(_, n)| n == '*') {
            chars.next();
            let mut previous = ' ';
            for (_, n) in chars.by_ref() {
                if previous == '*' && n == '/' {
                    break;
                }
                previous = n;
            }
            continue;
        }
        let kind = if c == '\'' || c == '"' {
            let (value, end) = string(source, start, c);
            // Consume what `string` read.
            while chars.next_if(|&(i, _)| i < end).is_some() {}
            tokens.push(Token {
                kind: Kind::Str {
                    value,
                    interpolates: c == '"',
                },
                start,
                end,
            });
            continue;
        } else if c.is_alphabetic() || c == '_' {
            let mut name = String::from(c);
            while let Some((_, n)) = chars.next_if(|&(_, n)| n.is_alphanumeric() || n == '_') {
                name.push(n);
            }
            Kind::Ident(name)
        } else {
            Kind::Punct(c)
        };
        let end = chars.peek().map_or(source.len(), |&(i, _)| i);
        tokens.push(Token { kind, start, end });
    }
    tokens
}

/// The string literal that opens at `start` with `quote` (single or triple),
/// and where it ends.
fn string(source: &str, start: usize, quote: char) -> (String, usize) {
    let rest = &source[start..];
    let closing = quote.to_string().repeat(3);
    let triple = rest.starts_with(&closing);
    let opening = if triple { 3 } else { 1 };
    let mut value = String::new();
    let mut escaped = false;
    let mut end = source.len();
    let body = &rest[opening..];
    for (offset, c) in body.char_indices() {
        let here = start + opening + offset;
        if escaped {
            value.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if triple && body[offset..].starts_with(&closing) {
            end = here + 3;
            break;
        } else if !triple && c == quote {
            end = here + 1;
            break;
        } else if !triple && c == '\n' {
            end = here;
            break;
        } else {
            value.push(c);
        }
    }
    (value, end)
}

fn ident(token: &Token) -> Option<&str> {
    match &token.kind {
        Kind::Ident(name) => Some(name),
        _ => None,
    }
}

fn punct(token: Option<&Token>, c: char) -> bool {
    token.is_some_and(|t| t.kind == Kind::Punct(c))
}

fn literal(token: Option<&Token>) -> Option<(&str, bool)> {
    match &token?.kind {
        Kind::Str {
            value,
            interpolates,
        } => Some((value, *interpolates)),
        _ => None,
    }
}

/// `name = "value"` anywhere (`val`, `def`, `ext { }`, `ext.name =`),
/// `extra["name"] = "value"` and `val name by extra("value")`.
fn variables(tokens: &[Token]) -> HashMap<String, String> {
    let mut variables = HashMap::new();
    for (i, token) in tokens.iter().enumerate() {
        let at = |n: usize| tokens.get(i + n);
        if let Some(name) = ident(token) {
            if punct(at(1), '=') && !punct(at(2), '=') {
                if let Some((value, _)) = literal(at(2)) {
                    variables.insert(name.to_owned(), value.to_owned());
                }
            } else if name == "extra"
                && punct(at(1), '[')
                && punct(at(3), ']')
                && punct(at(4), '=')
                && let (Some((key, _)), Some((value, _))) = (literal(at(2)), literal(at(5)))
            {
                variables.insert(key.to_owned(), value.to_owned());
            } else if at(1).and_then(ident) == Some("by")
                && at(2).and_then(ident) == Some("extra")
                && punct(at(3), '(')
                && let Some((value, _)) = literal(at(4))
            {
                variables.insert(name.to_owned(), value.to_owned());
            }
        }
    }
    variables
}

struct Declared {
    configuration: String,
    group: String,
    artifact: String,
    version: Option<String>,
    start: usize,
    end: usize,
}

/// A dependency configuration: the well-known ones, and the variants a plugin
/// adds (`androidTestImplementation`, `debugApi`...).
fn is_configuration(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "api",
        "implementation",
        "compile",
        "compileOnly",
        "compileOnlyApi",
        "runtime",
        "runtimeOnly",
        "annotationProcessor",
        "kapt",
        "ksp",
        "classpath",
        "developmentOnly",
        "providedCompile",
        "providedRuntime",
    ];
    const SUFFIXES: &[&str] = &[
        "Implementation",
        "Api",
        "Compile",
        "CompileOnly",
        "Runtime",
        "RuntimeOnly",
        "AnnotationProcessor",
    ];
    NAMES.contains(&name)
        || (name.starts_with(char::is_lowercase)
            && SUFFIXES.iter().any(|suffix| name.ends_with(suffix)))
}

fn declarations(tokens: &[Token], variables: &HashMap<String, String>) -> Vec<Declared> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let configuration = ident(&tokens[i]).filter(|name| is_configuration(name));
        let after_dot = i > 0 && punct(tokens.get(i - 1), '.');
        let Some(configuration) = configuration.filter(|_| !after_dot) else {
            i += 1;
            continue;
        };
        let (coordinates, next) = arguments(tokens, i + 1, variables);
        for (group, artifact, version) in coordinates {
            found.push(Declared {
                configuration: configuration.to_owned(),
                group,
                artifact,
                version,
                start: tokens[i].start,
                end: tokens[next.saturating_sub(1).max(i)].end,
            });
        }
        i = next.max(i + 1);
    }
    found
}

type Coordinates = (String, String, Option<String>);

/// The dependencies the arguments from `from` declare, and the index of the
/// first token after them: `"g:a:v"`, `platform("g:a:v")`, several separated
/// by commas, or `group: "g", name: "a", version: "v"`.
fn arguments(
    tokens: &[Token],
    from: usize,
    variables: &HashMap<String, String>,
) -> (Vec<Coordinates>, usize) {
    let mut found = Vec::new();
    let mut i = from;
    let mut parenthesized = false;
    if punct(tokens.get(i), '(') {
        parenthesized = true;
        i += 1;
    }
    loop {
        let before = i;
        let token = tokens.get(i);
        if let Some((value, interpolates)) = literal(token) {
            found.extend(coordinates(value, interpolates, variables));
            i += 1;
        } else if matches!(token.and_then(ident), Some("platform" | "enforcedPlatform"))
            && punct(tokens.get(i + 1), '(')
        {
            if let Some((value, interpolates)) = literal(tokens.get(i + 2)) {
                found.extend(coordinates(value, interpolates, variables));
            }
            i += 3;
            if punct(tokens.get(i), ')') {
                i += 1;
            }
        } else if token.and_then(ident).is_some()
            && (punct(tokens.get(i + 1), ':') || punct(tokens.get(i + 1), '='))
        {
            let (named, next) = named(tokens, i, variables);
            found.extend(named);
            i = next;
        }
        if i == before {
            break;
        }
        if punct(tokens.get(i), ',') {
            i += 1;
        } else {
            break;
        }
    }
    if parenthesized && punct(tokens.get(i), ')') {
        i += 1;
    }
    (found, i)
}

/// `group: "g", name: "a", version: "v"` (or `group = "g"`), in any order;
/// stops at the first thing that is not a `name: "string"` pair.
fn named(
    tokens: &[Token],
    from: usize,
    variables: &HashMap<String, String>,
) -> (Option<Coordinates>, usize) {
    let (mut group, mut artifact, mut version) = (None, None, None);
    let mut i = from;
    while let Some(key) = tokens.get(i).and_then(ident) {
        if !(punct(tokens.get(i + 1), ':') || punct(tokens.get(i + 1), '=')) {
            break;
        }
        let Some((value, interpolates)) = literal(tokens.get(i + 2)) else {
            break;
        };
        let value = interpolate(value, interpolates, variables);
        match key {
            "group" => group = value,
            "name" => artifact = value,
            "version" => version = value,
            _ => {}
        }
        i += 3;
        if punct(tokens.get(i), ',') && tokens.get(i + 1).and_then(ident).is_some() {
            i += 1;
        } else {
            break;
        }
    }
    let coordinates = group.zip(artifact).map(|(g, a)| (g, a, version));
    (coordinates, i)
}

/// `group:artifact[:version[:classifier]][@extension]`; no version when the
/// script leaves it to a platform (BOM) or to a variable it does not define.
fn coordinates(
    value: &str,
    interpolates: bool,
    variables: &HashMap<String, String>,
) -> Option<Coordinates> {
    let mut parts = value.split(':');
    let group = interpolate(parts.next()?, interpolates, variables)?;
    let artifact = interpolate(parts.next()?, interpolates, variables)?;
    let version = parts
        .next()
        .map(|v| v.split('@').next().unwrap_or(v))
        .and_then(|v| interpolate(v, interpolates, variables));
    // A plugin id or a stray string is not a dependency.
    (!group.is_empty() && !artifact.is_empty() && !group.contains(char::is_whitespace))
        .then_some((group, artifact, version))
}

/// `$name` and `${name}` replaced by the variables the script defines;
/// `None` when one is not defined (or the text is empty).
fn interpolate(
    text: &str,
    interpolates: bool,
    variables: &HashMap<String, String>,
) -> Option<String> {
    if !interpolates || !text.contains('$') {
        return (!text.is_empty()).then(|| text.to_owned());
    }
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        let (name, after) = if let Some(braced) = rest.strip_prefix('{') {
            let close = braced.find('}')?;
            (&braced[..close], &braced[close + 1..])
        } else {
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };
        out.push_str(variables.get(name)?);
        rest = after;
    }
    out.push_str(rest);
    (!out.is_empty()).then_some(out)
}
