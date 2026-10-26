//! `java.util.Properties` syntax.

use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, SourceUnit};

use super::location;
use crate::{Frontend, LangError};

#[derive(Debug, Clone, Copy, Default)]
pub struct PropertiesFrontend;

impl Frontend for PropertiesFrontend {
    fn language(&self) -> Language {
        Language::Properties
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["properties"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let mut unit = SourceUnit::new(path, Language::Properties);
        for entry in properties(source) {
            let location = location(source, entry.value_start, entry.value_end);
            let kind = FactKind::Property {
                key: entry.key,
                value: entry.value,
            };
            unit.push(kind, SourceUnit::ROOT, location);
        }
        Ok(unit)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    key: String,
    value: String,
    /// Byte range of the value's first physical line in the source.
    value_start: usize,
    value_end: usize,
}

/// Parses `java.util.Properties` syntax: `#`/`!` comments, `=`, `:` or
/// whitespace separators, `\` line continuations and escapes.
fn properties(source: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut lines = line_spans(source).into_iter().peekable();
    while let Some((start, end)) = lines.next() {
        let line = &source[start..end];
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with(['#', '!']) {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let (key, rest) = split_key(trimmed);
        let value_offset = start + indent + (trimmed.len() - rest.len());

        let mut logical = rest.to_owned();
        while ends_with_continuation(&logical) {
            logical.pop();
            match lines.next() {
                Some((s, e)) => logical.push_str(source[s..e].trim_start()),
                None => break,
            }
        }
        entries.push(Entry {
            key: unescape(key),
            value: unescape(&logical).trim_end().to_owned(),
            value_start: value_offset,
            value_end: end,
        });
    }
    entries
}

/// `(start, end)` byte offsets of each line, without the line terminator.
fn line_spans(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (i, c) in source.char_indices() {
        if c == '\n' {
            let end = if source[..i].ends_with('\r') {
                i - 1
            } else {
                i
            };
            spans.push((start, end));
            start = i + 1;
        }
    }
    if start < source.len() {
        spans.push((start, source.len()));
    }
    spans
}

/// Splits `key = value`, `key: value` or `key value` (separators may be escaped
/// inside the key). Returns the raw key and the raw value text.
fn split_key(line: &str) -> (&str, &str) {
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '=' | ':' | ' ' | '\t' | '\u{c}' => {
                let rest = line[i..].trim_start_matches([' ', '\t', '\u{c}']);
                let rest = rest
                    .strip_prefix(['=', ':'])
                    .map_or(rest, |r| r.trim_start_matches([' ', '\t', '\u{c}']));
                return (&line[..i], rest);
            }
            _ => {}
        }
    }
    (line, "")
}

/// An odd number of trailing backslashes continues the line.
fn ends_with_continuation(text: &str) -> bool {
    text.chars().rev().take_while(|c| *c == '\\').count() % 2 == 1
}

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(decoded) => out.push(decoded),
                    None => out.push_str(&hex),
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}
