//! Kotlin literal syntax: string templates, raw strings and integer literals.

use tree_sitter::Node;

use super::syntax::text;

/// Value of an integer literal: decimal, `0x` or `0b`, with `_` separators and
/// `L` / `u` suffixes. Kotlin has no octal literals.
pub(super) fn int_value(text: &str) -> Option<i64> {
    let digits: String = text.chars().filter(|c| *c != '_').collect();
    let digits = digits.trim_end_matches(['l', 'L', 'u', 'U']);
    let lower = digits.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = lower.strip_prefix("0b") {
        i64::from_str_radix(bin, 2).ok()
    } else {
        lower.parse().ok()
    }
}

/// Decoded value of a string literal (`"..."` or raw `"""..."""`), or `None`
/// when it is a template with interpolations: its value is only known at run
/// time.
///
/// The grammar's split of a literal into parts is not reliable (`"AES_$bits"`
/// and unicode escapes may stay plain content), so the text is decoded here.
pub(super) fn string_value(node: Node<'_>, src: &str) -> Option<String> {
    let mut body = String::new();
    let mut cursor = node.walk();
    for part in node.named_children(&mut cursor) {
        match part.kind() {
            "string_content" | "escape_sequence" => body.push_str(text(part, src)),
            "interpolation" => return None,
            _ => {}
        }
    }
    decode(&body, node.kind() == "multiline_string_literal")
}

/// Raw strings have no escapes; both kinds have templates.
fn decode(body: &str, raw: bool) -> Option<String> {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if !raw => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('b') => out.push('\u{8}'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(decoded) => out.push(decoded),
                        None => {
                            out.push_str("\\u");
                            out.push_str(&hex);
                        }
                    }
                }
                // `\$`, `\"`, `\'`, `\\`.
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            '$' if chars
                .peek()
                .is_some_and(|n| n.is_alphabetic() || *n == '_' || *n == '{') =>
            {
                return None;
            }
            _ => out.push(c),
        }
    }
    Some(out)
}

/// One part of a string template.
#[derive(Debug, PartialEq)]
pub(super) enum TemplatePart {
    Text(String),
    /// `$name` or `${name}`.
    Name(String),
    /// `${expression}`.
    Unknown,
}

/// The parts of a string literal with interpolations, read from its text
/// like [`string_value`]: `"$alg/ECB/${padding}"` -> name, text, name.
pub(super) fn template_parts(node: Node<'_>, src: &str) -> Option<Vec<TemplatePart>> {
    let raw = node.kind() == "multiline_string_literal";
    let quote = if raw { "\"\"\"" } else { "\"" };
    let body = text(node, src).strip_prefix(quote)?.strip_suffix(quote)?;
    let mut parts = Vec::new();
    let mut chunk = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if !raw => {
                chunk.push(c);
                chunk.extend(chars.next());
            }
            '$' if chars.peek() == Some(&'{') => {
                chars.next();
                let inner: String = chars.by_ref().take_while(|c| *c != '}').collect();
                flush(&mut chunk, &mut parts, raw)?;
                parts.push(if is_identifier(inner.trim()) {
                    TemplatePart::Name(inner.trim().to_owned())
                } else {
                    TemplatePart::Unknown
                });
            }
            '$' if chars.peek().is_some_and(|n| n.is_alphabetic() || *n == '_') => {
                flush(&mut chunk, &mut parts, raw)?;
                let mut name = String::new();
                while let Some(n) = chars.next_if(|n| n.is_alphanumeric() || *n == '_') {
                    name.push(n);
                }
                parts.push(TemplatePart::Name(name));
            }
            _ => chunk.push(c),
        }
    }
    flush(&mut chunk, &mut parts, raw)?;
    Some(parts)
}

fn flush(chunk: &mut String, parts: &mut Vec<TemplatePart>, raw: bool) -> Option<()> {
    if !chunk.is_empty() {
        parts.push(TemplatePart::Text(decode(chunk, raw)?));
        chunk.clear();
    }
    Some(())
}

fn is_identifier(text: &str) -> bool {
    text.chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_')
        && text.chars().all(|c| c.is_alphanumeric() || c == '_')
}
