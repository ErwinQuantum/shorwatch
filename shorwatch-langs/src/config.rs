//! Configuration frontends: `.properties` and YAML.
//!
//! Both flatten entries the way Spring Boot names them (`a.b[0].c`) and emit
//! one [`FactKind::Property`] per scalar value, located at the value. Nothing
//! is interpreted: profiles, placeholders (`${...}`) and anchors are left
//! as written, and comments produce nothing.

use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, Location, Position, SourceUnit};
use tree_sitter::{Node, Parser};

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

#[derive(Debug, Clone, Copy, Default)]
pub struct YamlFrontend;

impl Frontend for YamlFrontend {
    fn language(&self) -> Language {
        Language::Yaml
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["yml", "yaml"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_yaml::LANGUAGE.into())
            .map_err(|e| LangError::Grammar(Language::Yaml, e.to_string()))?;
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| LangError::Parse(path.to_owned()))?;
        let mut lowering = YamlLowering {
            src: source,
            unit: SourceUnit::new(path, Language::Yaml),
        };
        lowering.walk(tree.root_node(), String::new());
        Ok(lowering.unit)
    }
}

struct YamlLowering<'s> {
    src: &'s str,
    unit: SourceUnit,
}

impl YamlLowering<'_> {
    /// Configuration files nest a handful of levels, so plain recursion is fine.
    fn walk(&mut self, node: Node<'_>, prefix: String) {
        match node.kind() {
            "block_mapping" | "flow_mapping" => {
                let mut cursor = node.walk();
                let pairs: Vec<_> = node.named_children(&mut cursor).collect();
                for pair in pairs {
                    let key = pair.child_by_field_name("key").and_then(|k| self.scalar(k));
                    if let (Some(key), Some(value)) = (key, pair.child_by_field_name("value")) {
                        self.walk(value, join(&prefix, &key));
                    }
                }
            }
            "block_sequence" | "flow_sequence" => {
                let mut cursor = node.walk();
                let items: Vec<_> = node
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .collect();
                for (i, item) in items.into_iter().enumerate() {
                    self.walk(item, format!("{prefix}[{i}]"));
                }
            }
            "plain_scalar" | "double_quote_scalar" | "single_quote_scalar" | "block_scalar" => {
                if let Some(value) = self.scalar(node) {
                    let location = location(self.src, node.start_byte(), node.end_byte());
                    let kind = FactKind::Property { key: prefix, value };
                    self.unit.push(kind, SourceUnit::ROOT, location);
                }
            }
            // Each document of a stream starts again from the root.
            "document" | "stream" => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                for child in children {
                    self.walk(child, String::new());
                }
            }
            // Wrappers (block/flow nodes, sequence items, anchors, tags).
            _ => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                for child in children {
                    self.walk(child, prefix.clone());
                }
            }
        }
    }

    /// The text of a scalar node (or of the scalar inside a wrapper), unquoted.
    fn scalar(&self, node: Node<'_>) -> Option<String> {
        let text = &self.src[node.byte_range()];
        match node.kind() {
            "plain_scalar" => Some(text.trim().to_owned()),
            "single_quote_scalar" => Some(text[1..text.len() - 1].replace("''", "'")),
            "double_quote_scalar" => Some(text[1..text.len() - 1].replace("\\\"", "\"")),
            "block_scalar" => text
                .split_once('\n')
                .map(|(_, body)| body.trim().to_owned()),
            "comment" | "anchor" | "tag" | "alias" => None,
            _ => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                children.into_iter().find_map(|c| self.scalar(c))
            }
        }
    }
}

fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

/// Location of `start..end`, with columns in code points like the Java frontend.
fn location(src: &str, start: usize, end: usize) -> Location {
    Location {
        start: position(src, start),
        end: position(src, end),
        start_byte: start,
        end_byte: end,
    }
}

fn position(src: &str, byte: usize) -> Position {
    let before = &src[..byte];
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    Position {
        line: u32::try_from(before.matches('\n').count() + 1).unwrap_or(u32::MAX),
        column: u32::try_from(src[line_start..byte].chars().count() + 1).unwrap_or(u32::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(unit: &SourceUnit) -> Vec<(String, String, u32)> {
        unit.facts()
            .iter()
            .filter_map(|f| match &f.kind {
                FactKind::Property { key, value } => {
                    Some((key.clone(), value.clone(), f.location.start.line))
                }
                _ => None,
            })
            .collect()
    }

    fn owned(expected: &[(&str, &str, u32)]) -> Vec<(String, String, u32)> {
        expected
            .iter()
            .map(|(k, v, l)| ((*k).to_owned(), (*v).to_owned(), *l))
            .collect()
    }

    #[test]
    fn flattens_yaml_like_spring() {
        let source = "\
# comment: ignored
spring:
  security:
    oauth2.resourceserver.jwt:
      jws-algorithms: [RS256, \"ES256\"]
jwt:
  algorithms:
    - PS256
    - 'Ed''25519'
  inline: { alg: RS512 }
  note: |
    multi
---
server.ssl.ciphers: TLS_RSA_WITH_AES_128_CBC_SHA
";
        let unit = YamlFrontend.lower("application.yml", source).unwrap();
        assert_eq!(
            entries(&unit),
            owned(&[
                (
                    "spring.security.oauth2.resourceserver.jwt.jws-algorithms[0]",
                    "RS256",
                    5
                ),
                (
                    "spring.security.oauth2.resourceserver.jwt.jws-algorithms[1]",
                    "ES256",
                    5
                ),
                ("jwt.algorithms[0]", "PS256", 8),
                ("jwt.algorithms[1]", "Ed'25519", 9),
                ("jwt.inline.alg", "RS512", 10),
                ("jwt.note", "multi", 11),
                ("server.ssl.ciphers", "TLS_RSA_WITH_AES_128_CBC_SHA", 14),
            ])
        );
    }

    #[test]
    fn yaml_value_location_points_at_the_value() {
        let unit = YamlFrontend.lower("a.yml", "jwt:\n  alg: RS256\n").unwrap();
        let start = unit.facts()[0].location.start;
        assert_eq!((start.line, start.column), (2, 8));
    }

    #[test]
    fn parses_properties_syntax() {
        let source = "\
# comment
! also a comment
jwt.algorithm=RS256
server.ssl.ciphers : TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\\
    TLS_RSA_WITH_AES_256_CBC_SHA
key\\ with\\ spaces value
empty=
encrypt.key-store.location classpath:/server.jks
";
        let unit = PropertiesFrontend
            .lower("application.properties", source)
            .unwrap();
        assert_eq!(
            entries(&unit),
            owned(&[
                ("jwt.algorithm", "RS256", 3),
                (
                    "server.ssl.ciphers",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA",
                    4
                ),
                ("key with spaces", "value", 6),
                ("empty", "", 7),
                ("encrypt.key-store.location", "classpath:/server.jks", 8),
            ])
        );
        let start = unit.facts()[0].location.start;
        assert_eq!((start.line, start.column), (3, 15));
    }

    #[test]
    fn handles_crlf_line_endings() {
        let unit = PropertiesFrontend
            .lower("a.properties", "a=1\r\nb=2\r\n")
            .unwrap();
        assert_eq!(entries(&unit), owned(&[("a", "1", 1), ("b", "2", 2)]));
    }
}
