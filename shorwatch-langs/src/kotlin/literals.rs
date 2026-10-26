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
