//! Where a finding's lines open outside the report: in the editor on this
//! machine, or on the repository host at the scanned commit.

use std::fmt::Write as _;

use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SourceLinks {
    /// The folder finding paths are relative to, absolute and with forward
    /// slashes, when the scanned files are on this machine: they open in
    /// VS Code (`vscode://file/...`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_root: Option<String>,
    /// The repository host, when the scan runs in its CI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<WebLinks>,
}

/// URL templates with `{path}` (percent-encoded, relative to the scan's
/// working directory), `{line}` and `{end}` placeholders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebLinks {
    /// "GitHub", "GitLab": the links read "View on GitHub".
    pub host: String,
    /// The file at the scanned commit, the lines highlighted.
    pub file: String,
    /// The file in an editor in the browser (github.dev).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,
}

impl WebLinks {
    /// `path:line` (through `end`) on the host; `None` for paths outside the
    /// working directory, which the host cannot know.
    pub fn file(&self, path: &str, line: u32, end: u32) -> Option<String> {
        fill(&self.file, path, line, end)
    }
}

fn fill(template: &str, path: &str, line: u32, end: u32) -> Option<String> {
    if path.starts_with('/') || path.contains(':') || path.split('/').any(|s| s == "..") {
        return None;
    }
    Some(
        template
            .replace("{path}", &encode_path(path))
            .replace("{line}", &line.to_string())
            .replace("{end}", &end.max(line).to_string()),
    )
}

/// Percent-encodes each segment of a `/`-separated path.
pub fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-_.~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github() -> WebLinks {
        WebLinks {
            host: "GitHub".into(),
            file: "https://github.com/acme/pay/blob/abc/{path}#L{line}-L{end}".into(),
            editor: None,
        }
    }

    #[test]
    fn files_link_to_their_lines() {
        assert_eq!(
            github().file("src/My File.java", 4, 6).as_deref(),
            Some("https://github.com/acme/pay/blob/abc/src/My%20File.java#L4-L6")
        );
        assert_eq!(
            github().file("a.yml", 9, 0).as_deref(),
            Some("https://github.com/acme/pay/blob/abc/a.yml#L9-L9")
        );
    }

    #[test]
    fn paths_outside_the_working_directory_have_no_link() {
        assert_eq!(github().file("/etc/ssl/cert.pem", 1, 1), None);
        assert_eq!(github().file("C:/certs/a.pem", 1, 1), None);
        assert_eq!(github().file("../other/a.pem", 1, 1), None);
    }
}
