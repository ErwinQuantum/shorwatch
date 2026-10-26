//! Word wrapping for advice text.

/// Wraps `text` at `width` columns. Continuation lines start with `indent`;
/// the first line does not, so callers can put a label in front of it.
pub(super) fn wrap(text: &str, width: usize, indent: &str) -> String {
    let width = width.max(20);
    let mut out = String::new();
    let mut line_len = 0;
    for word in text.split_whitespace() {
        let len = word.chars().count();
        if line_len > 0 && line_len + 1 + len > width {
            out.push('\n');
            out.push_str(indent);
            line_len = 0;
        } else if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_on_word_boundaries_with_indent() {
        let text = "one two three four five six seven eight nine ten eleven twelve";
        assert_eq!(
            wrap(text, 20, "> "),
            "one two three four\n> five six seven eight\n> nine ten eleven\n> twelve"
        );
    }

    #[test]
    fn long_words_are_not_split() {
        assert_eq!(
            wrap("a verylongwordthatdoesnotfit b", 20, ""),
            "a\nverylongwordthatdoesnotfit\nb"
        );
    }
}
