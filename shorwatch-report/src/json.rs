//! The findings as JSON, for scripts and other tools. The shape mirrors the
//! core [`Finding`](shorwatch_core::Finding) type, wrapped with the tool
//! version and the summary.

use serde::Serialize;
use shorwatch_core::Finding;

use crate::{Scan, Summary};

#[derive(Serialize)]
struct Report<'a> {
    tool: &'static str,
    version: &'a str,
    summary: Summary,
    findings: &'a [Finding],
}

pub fn render(scan: &Scan) -> String {
    let report = Report {
        tool: "shorwatch",
        version: &scan.tool_version,
        summary: scan.summary(),
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
        assert_eq!(value["summary"]["findings"], 4);
        assert_eq!(value["findings"][0]["rule_id"], "jvm.jca.rsa");
        assert_eq!(value["findings"][0]["location"]["start"]["line"], 5);
        assert_eq!(value["findings"][2]["status"], "in_transition");
    }
}
