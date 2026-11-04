//! The findings as JSON, for scripts and other tools. The shape mirrors the
//! core [`Finding`](shorwatch_core::Finding) type, wrapped with the tool
//! version, the summary and the projects.

use serde::Serialize;
use shorwatch_core::{Dependency, Finding};

use crate::{Project, Scan, Summary, Suppressed};

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
    /// Findings ignored in the code or already in the baseline.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    suppressed: &'a [Suppressed],
    /// The cryptographic libraries the build files declare: an inventory,
    /// apart from the findings.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    dependencies: &'a [Dependency],
}

pub fn render(scan: &Scan) -> String {
    let report = Report {
        tool: "shorwatch",
        version: &scan.tool_version,
        summary: scan.summary(),
        projects: &scan.projects,
        findings: &scan.findings,
        suppressed: &scan.suppressed,
        dependencies: &scan.dependencies,
    };
    // Plain data with string keys: serialization cannot fail.
    serde_json::to_string_pretty(&report).expect("report serializes") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn libraries_are_listed_apart_from_the_findings() {
        let mut scan = scan();
        let value: serde_json::Value = serde_json::from_str(&render(&scan)).unwrap();
        assert!(
            value.get("dependencies").is_none(),
            "nothing declared, nothing listed"
        );
        assert!(value["summary"].get("libraries").is_none());

        scan.dependencies = crate::fixtures::dependencies();
        let value: serde_json::Value = serde_json::from_str(&render(&scan)).unwrap();
        assert_eq!(
            value["summary"]["findings"], 5,
            "libraries are not findings"
        );
        assert_eq!(value["summary"]["libraries"], 4);
        assert_eq!(value["dependencies"][0]["library_id"], "bouncycastle");
        assert_eq!(
            value["dependencies"][0]["post_quantum"]["support"],
            "too_old"
        );
        assert_eq!(value["dependencies"][0]["location"]["start"]["line"], 33);
        assert_eq!(value["dependencies"][1]["role"], "jwt");
        assert!(value["dependencies"][1].get("post_quantum").is_none());
        assert_eq!(
            value["dependencies"][3]["post_quantum"]["support"],
            "unknown"
        );
    }

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
