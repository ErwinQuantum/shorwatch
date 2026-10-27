//! The findings as JSON, for scripts and other tools. The shape mirrors the
//! core [`Finding`](shorwatch_core::Finding) type, wrapped with the tool
//! version, the summary and the projects.

use serde::Serialize;
use shorwatch_core::Finding;

use crate::{Project, Scan, Summary};

#[derive(Serialize)]
struct Report<'a> {
    tool: &'static str,
    version: &'a str,
    summary: Summary,
    /// The projects scanned together; a finding belongs to the one with the
    /// longest `root` its path is under.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    projects: &'a [Project],
    findings: &'a [Finding],
}

pub fn render(scan: &Scan) -> String {
    let report = Report {
        tool: "shorwatch",
        version: &scan.tool_version,
        summary: scan.summary(),
        projects: &scan.projects,
        findings: &scan.findings,
    };
    // Plain data with string keys: serialization cannot fail.
    serde_json::to_string_pretty(&report).expect("report serializes") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn json_round_trips_the_findings() {
        let value: serde_json::Value = serde_json::from_str(&render(&scan())).unwrap();
        assert_eq!(value["summary"]["findings"], 5);
        assert_eq!(value["summary"]["in_tests"], 1);
        assert_eq!(value["findings"][4]["role"], "test");
        assert_eq!(value["findings"][0]["rule_id"], "jvm.jca.rsa");
        assert_eq!(value["findings"][0]["location"]["start"]["line"], 5);
        assert_eq!(value["findings"][2]["status"], "in_transition");
    }
}
