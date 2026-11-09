//! C# literal syntax: regular, verbatim and raw string literals, and integers.

/// Value of an integer literal in decimal, hexadecimal or binary, with `_`
/// separators and the `u`/`l` suffixes.
pub(super) fn int_value(text: &str) -> Option<i64> {
    let digits: String = text.chars().filter(|c| *c != '_').collect();
    let lower = digits.to_ascii_lowercase();
    let lower = lower.trim_end_matches(['u', 'l']);
    if let Some(hex) = lower.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = lower.strip_prefix("0b") {
        i64::from_str_radix(bin, 2).ok()
    } else {
        lower.parse().ok()
    }
}

/// Decoded value of a string literal as written in `text`: `"a\n"`,
/// `@"a""b"` or `"""a"""`. Interpolated strings are not literals.
pub(super) fn string_value(text: &str) -> Option<String> {
    if let Some(verbatim) = text.strip_prefix("@\"") {
        let body = verbatim.strip_suffix('"')?;
        return Some(body.replace("\"\"", "\""));
    }
    if text.starts_with("\"\"\"") {
        let quotes = text.chars().take_while(|c| *c == '"').count();
        let body = text.get(quotes..text.len().checked_sub(quotes)?)?;
        return Some(body.trim().to_owned());
    }
    let body = text.strip_prefix('"')?.strip_suffix('"')?;
    Some(unescape(body))
}

fn unescape(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('a') => out.push('\u{7}'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('v') => out.push('\u{b}'),
            Some('0') => out.push('\0'),
            Some(kind @ ('u' | 'U')) => {
                let width = if kind == 'u' { 4 } else { 8 };
                let hex: String = chars.by_ref().take(width).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(decoded) => out.push(decoded),
                    None => {
                        out.push('\\');
                        out.push(kind);
                        out.push_str(&hex);
                    }
                }
            }
            Some('x') => {
                let mut hex = String::new();
                while hex.len() < 4 && chars.peek().is_some_and(char::is_ascii_hexdigit) {
                    hex.extend(chars.next());
                }
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(decoded) => out.push(decoded),
                    None => out.push_str("\\x"),
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}
