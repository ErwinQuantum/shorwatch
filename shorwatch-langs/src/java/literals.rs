//! Java literal syntax: string literals, text blocks and integer literals.

/// Value of an integer literal in any base, with `_` separators and an
/// optional `L` suffix.
pub(super) fn int_value(text: &str) -> Option<i64> {
    let digits: String = text.chars().filter(|c| *c != '_').collect();
    let digits = digits.trim_end_matches(['l', 'L']);
    let lower = digits.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = lower.strip_prefix("0b") {
        i64::from_str_radix(bin, 2).ok()
    } else if lower.len() > 1 && lower.starts_with('0') {
        i64::from_str_radix(&lower[1..], 8).ok()
    } else {
        lower.parse().ok()
    }
}

/// Decoded value of a string literal or text block, as written in `text`.
pub(super) fn string_value(text: &str) -> Option<String> {
    if let Some(body) = text
        .strip_prefix("\"\"\"")
        .and_then(|t| t.strip_suffix("\"\"\""))
    {
        // Text block content starts on the line after the opening delimiter.
        let body = body.split_once('\n').map_or(body, |(_, rest)| rest);
        return Some(unescape(body));
    }
    let body = text.strip_prefix('"')?.strip_suffix('"')?;
    Some(unescape(body))
}

fn unescape(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('s') => out.push(' '),
            Some('0') => out.push('\0'),
            Some('u') => {
                let hex: String = chars.by_ref().skip_while(|c| *c == 'u').take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(decoded) => out.push(decoded),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}
