//! What the runtime decides and a scan of the files cannot read, said once
//! per scan (see [`shorwatch_core::Note`]).
//!
//! A project with no explicit TLS setting looks the same as one that has
//! been migrated, though the groups a connection negotiates come from the
//! runtime and the other peer. The note keeps that silence from reading as
//! clean, and never claims either outcome.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeNote {
    pub id: String,
    /// What the runtime decides, e.g. `TLS`.
    pub topic: String,
    /// The sentence that says it is decided elsewhere and not analyzed.
    pub text: String,
    /// Places where the topic is in play, explicit settings apart.
    pub uses: usize,
    /// Explicit settings read (cipher suites, named groups...), whatever
    /// their value.
    pub settings: usize,
}

impl RuntimeNote {
    /// `TLS: 3 explicit settings read; the key-exchange groups are decided...`
    pub fn line(&self) -> String {
        let read = match self.settings {
            0 => "no explicit setting read".to_owned(),
            1 => "1 explicit setting read".to_owned(),
            n => format!("{n} explicit settings read"),
        };
        format!("{}: {read}; {}", self.topic, self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(settings: usize) -> RuntimeNote {
        RuntimeNote {
            id: "tls-key-exchange".into(),
            topic: "TLS".into(),
            text: "decided at run time.".into(),
            uses: 2,
            settings,
        }
    }

    fn scan_with(settings: usize) -> crate::Scan {
        let mut scan = crate::fixtures::scan();
        scan.runtime = vec![tls(settings)];
        scan
    }

    #[test]
    fn every_format_says_it_once_and_the_terminal_wraps_it() {
        let scan = scan_with(3);
        let line = tls(3).line();

        let terminal = crate::terminal::render(&scan, &crate::terminal::Options::default());
        let terminal = anstream::adapter::strip_str(&terminal).to_string();
        assert_eq!(terminal.matches("TLS: 3 explicit settings read").count(), 1);

        assert_eq!(crate::markdown::render(&scan).matches(&line).count(), 1);

        let json: serde_json::Value = serde_json::from_str(&crate::json::render(&scan)).unwrap();
        assert_eq!(json["summary"]["runtime"][0]["settings"], 3);
        assert_eq!(json["summary"]["runtime"][0]["topic"], "TLS");

        let cbom: serde_json::Value = serde_json::from_str(&crate::cbom::render(&scan)).unwrap();
        let properties = cbom["metadata"]["properties"].as_array().unwrap();
        assert_eq!(properties.len(), 1);
        assert_eq!(properties[0]["name"], "shorwatch:runtime-decided");
        assert_eq!(properties[0]["value"], line);

        // The HTML report carries it in its data, for the cover to read.
        assert!(crate::html::render(&scan).contains(r#""runtime""#));
    }

    #[test]
    fn a_scan_without_notes_says_nothing_about_the_runtime() {
        let scan = crate::fixtures::scan();
        let json: serde_json::Value = serde_json::from_str(&crate::json::render(&scan)).unwrap();
        assert!(json["summary"].get("runtime").is_none());
        let cbom: serde_json::Value = serde_json::from_str(&crate::cbom::render(&scan)).unwrap();
        assert!(cbom["metadata"].get("properties").is_none());
    }

    #[test]
    fn the_line_counts_the_settings_it_read() {
        assert_eq!(
            tls(0).line(),
            "TLS: no explicit setting read; decided at run time."
        );
        assert_eq!(
            tls(1).line(),
            "TLS: 1 explicit setting read; decided at run time."
        );
        assert_eq!(
            tls(3).line(),
            "TLS: 3 explicit settings read; decided at run time."
        );
    }
}
