//! Text from the scanned files made safe to print. File names, keystore
//! aliases, literals and source lines come from whoever wrote the repository:
//! a control character in them could rewrite the terminal (ANSI escapes) or,
//! after a newline, issue workflow commands in a CI log (`::add-mask::`).
//! Each one becomes U+FFFD, one code point for one, so columns still match.

use shorwatch_report::Scan;

/// Every text of the scan that came from the scanned files.
pub fn scan(scan: &mut Scan) {
    for finding in &mut scan.findings {
        line(&mut finding.path);
        if let Some(detail) = &mut finding.detail {
            line(detail);
        }
        for step in &mut finding.flow {
            if let Some(path) = &mut step.path {
                line(path);
            }
            line(&mut step.note);
        }
        if let Some(evidence) = &mut finding.hybrid_evidence {
            line(&mut evidence.text);
        }
    }
    for project in &mut scan.projects {
        line(&mut project.name);
        line(&mut project.root);
    }
    let sources = std::mem::take(&mut scan.sources);
    scan.sources = sources
        .into_iter()
        .map(|(mut path, mut text)| {
            line(&mut path);
            source(&mut text);
            (path, text)
        })
        .collect();
}

/// A message about a scanned file, for standard error.
pub fn text(text: &str) -> String {
    let mut text = text.to_owned();
    line(&mut text);
    text
}

fn line(text: &mut String) {
    if text.chars().any(unsafe_char) {
        *text = text
            .chars()
            .map(|c| if unsafe_char(c) { '\u{FFFD}' } else { c })
            .collect();
    }
}

/// Like [`line`], keeping line breaks (`\n`, `\r\n`) and tabs.
fn source(text: &mut String) {
    let mut chars = text.chars().peekable();
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    while let Some(c) = chars.next() {
        let keep = matches!(c, '\n' | '\t') || (c == '\r' && chars.peek() == Some(&'\n'));
        if unsafe_char(c) && !keep {
            out.push('\u{FFFD}');
            changed = true;
        } else {
            out.push(c);
        }
    }
    if changed {
        *text = out;
    }
}

/// C0 and C1 controls (ESC, CR, newline, DEL...) and the bidirectional
/// overrides that make text display in another order than it reads
/// ("Trojan Source").
fn unsafe_char(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_become_replacement_characters() {
        let mut path = "evil\n::add-mask::x\u{1b}[2J.pem".to_owned();
        line(&mut path);
        assert_eq!(path, "evil\u{FFFD}::add-mask::x\u{FFFD}[2J.pem");
    }

    #[test]
    fn sources_keep_their_line_breaks_and_columns() {
        let mut text = "a\tb\r\nc\u{1b}d\re\n\u{202E}f".to_owned();
        source(&mut text);
        assert_eq!(text, "a\tb\r\nc\u{FFFD}d\u{FFFD}e\n\u{FFFD}f");
        assert_eq!(
            text.chars().count(),
            "a\tb\r\nc\u{1b}d\re\n\u{202E}f".chars().count()
        );
    }

    #[test]
    fn plain_text_is_left_alone() {
        let mut text = "KeyPairGenerator.getInstance(\"RSA\"); // ñ, 鍵".to_owned();
        line(&mut text);
        assert_eq!(text, "KeyPairGenerator.getInstance(\"RSA\"); // ñ, 鍵");
    }
}
