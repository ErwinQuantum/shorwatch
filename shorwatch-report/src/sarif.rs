//! SARIF 2.1.0, the format GitHub code scanning, GitLab and IDE viewers read.
//!
//! Each distinct rule becomes a `reportingDescriptor` with its migration
//! advice as help text; each finding a `result` located by line and column
//! (Unicode code points). Mechanical fixes are attached as SARIF `fixes`.

use std::collections::BTreeMap;

use serde::Serialize;
use shorwatch_core::ir::Location;
use shorwatch_core::{CodeRole, Finding, Severity};

use crate::Scan;
use crate::summary::status_label;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/ErwinQuantum/shorwatch";

pub fn render(scan: &Scan) -> String {
    let rules = descriptors(&scan.findings);
    let index: BTreeMap<&str, usize> = rules.iter().enumerate().map(|(i, r)| (r.id, i)).collect();
    let log = Log {
        schema: SCHEMA,
        version: "2.1.0",
        runs: [Run {
            tool: Tool {
                driver: Driver {
                    name: "Shorwatch",
                    version: &scan.tool_version,
                    information_uri: INFORMATION_URI,
                    rules,
                },
            },
            column_kind: "unicodeCodePoints",
            results: scan
                .findings
                .iter()
                .map(|f| result(f, index[f.rule_id.as_str()]))
                .collect(),
        }],
    };
    // Plain data with string keys: serialization cannot fail.
    serde_json::to_string_pretty(&log).expect("SARIF serializes") + "\n"
}

fn descriptors(findings: &[Finding]) -> Vec<Descriptor<'_>> {
    let mut seen = BTreeMap::new();
    for finding in findings {
        seen.entry(finding.rule_id.as_str()).or_insert(finding);
    }
    seen.into_values()
        .map(|f| Descriptor {
            id: &f.rule_id,
            name: &f.algorithm,
            short_description: Text {
                text: f.title.clone(),
            },
            full_description: Text {
                text: f.message.clone(),
            },
            help: Help {
                text: f.suggestion.clone(),
                markdown: help_markdown(f),
            },
            help_uri: f.references.first().map(|r| r.url.as_str()),
            default_configuration: Configuration {
                level: level(f.severity),
            },
            properties: DescriptorProperties {
                tags: vec![
                    "security",
                    "cryptography",
                    "post-quantum",
                    match f.category {
                        shorwatch_core::Category::Shor => "shor",
                        shorwatch_core::Category::Grover => "grover",
                    },
                ],
                security_severity: security_severity(f.severity),
                precision: "high",
            },
        })
        .collect()
}

fn help_markdown(finding: &Finding) -> String {
    let mut text = finding.suggestion.clone();
    if !finding.references.is_empty() {
        text.push_str("\n\n**References**\n");
        for reference in &finding.references {
            text.push_str(&format!("\n- [{}]({})", reference.title, reference.url));
        }
    }
    text
}

fn result(finding: &Finding, rule_index: usize) -> SarifResult<'_> {
    let artifact = Artifact {
        uri: finding.path.replace('\\', "/"),
        uri_base_id: "%SRCROOT%",
    };
    SarifResult {
        rule_id: &finding.rule_id,
        rule_index,
        level: level(finding.severity),
        message: Text {
            text: match &finding.hybrid_evidence {
                Some(e) => format!(
                    "{} In transition: post-quantum code at line {} ({}).",
                    finding.message, e.location.start.line, e.text
                ),
                None => finding.message.clone(),
            },
        },
        locations: [ResultLocation {
            physical_location: PhysicalLocation {
                artifact_location: artifact.clone(),
                region: region(&finding.location),
            },
            message: None,
        }],
        code_flows: code_flows(finding, &artifact),
        fixes: finding
            .fix
            .iter()
            .map(|fix| Fix {
                description: Text {
                    text: fix.description.clone(),
                },
                artifact_changes: [Change {
                    artifact_location: artifact.clone(),
                    replacements: [Replacement {
                        deleted_region: region(&fix.location),
                        inserted_content: Content {
                            text: fix.replacement.clone(),
                        },
                    }],
                }],
            })
            .collect(),
        properties: ResultProperties {
            algorithm: &finding.algorithm,
            status: status_label(finding.status),
            role: finding.role,
            // GitHub code scanning filters results by tag.
            tags: match finding.role {
                CodeRole::Test => vec!["test"],
                CodeRole::Production => Vec::new(),
            },
        },
    }
}

/// The data-flow path as one thread flow: each step, then the use.
fn code_flows(finding: &Finding, artifact: &Artifact) -> Vec<CodeFlow> {
    if finding.flow.is_empty() {
        return Vec::new();
    }
    let step = |path: Option<&str>, location: &Location, note: &str| ThreadFlowLocation {
        location: ResultLocation {
            physical_location: PhysicalLocation {
                artifact_location: match path {
                    Some(path) => Artifact {
                        uri: path.replace('\\', "/"),
                        ..artifact.clone()
                    },
                    None => artifact.clone(),
                },
                region: region(location),
            },
            message: Some(Text { text: note.into() }),
        },
    };
    let locations = finding
        .flow
        .iter()
        .map(|s| step(s.path.as_deref(), &s.location, &s.note))
        .chain([step(None, &finding.location, "used here")])
        .collect();
    vec![CodeFlow {
        thread_flows: [ThreadFlow { locations }],
    }]
}

fn region(location: &Location) -> Region {
    Region {
        start_line: location.start.line,
        start_column: location.start.column,
        end_line: location.end.line,
        end_column: location.end.column,
    }
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub ranks code-scanning alerts by this CVSS-like score.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

#[derive(Serialize)]
struct Log<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [Run<'a>; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Run<'a> {
    tool: Tool<'a>,
    column_kind: &'static str,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver<'a> {
    name: &'static str,
    version: &'a str,
    information_uri: &'static str,
    rules: Vec<Descriptor<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor<'a> {
    id: &'a str,
    name: &'a str,
    short_description: Text,
    full_description: Text,
    help: Help,
    #[serde(skip_serializing_if = "Option::is_none")]
    help_uri: Option<&'a str>,
    default_configuration: Configuration,
    properties: DescriptorProperties,
}

#[derive(Serialize)]
struct Text {
    text: String,
}

#[derive(Serialize)]
struct Help {
    text: String,
    markdown: String,
}

#[derive(Serialize)]
struct Configuration {
    level: &'static str,
}

#[derive(Serialize)]
struct DescriptorProperties {
    tags: Vec<&'static str>,
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
    precision: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    rule_index: usize,
    level: &'static str,
    message: Text,
    locations: [ResultLocation; 1],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    code_flows: Vec<CodeFlow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fixes: Vec<Fix>,
    properties: ResultProperties<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultLocation {
    physical_location: PhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Text>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CodeFlow {
    thread_flows: [ThreadFlow; 1],
}

#[derive(Serialize)]
struct ThreadFlow {
    locations: Vec<ThreadFlowLocation>,
}

#[derive(Serialize)]
struct ThreadFlowLocation {
    location: ResultLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: Artifact,
    region: Region,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    uri: String,
    uri_base_id: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fix {
    description: Text,
    artifact_changes: [Change; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Change {
    artifact_location: Artifact,
    replacements: [Replacement; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Replacement {
    deleted_region: Region,
    inserted_content: Content,
}

#[derive(Serialize)]
struct Content {
    text: String,
}

#[derive(Serialize)]
struct ResultProperties<'a> {
    algorithm: &'a str,
    status: &'static str,
    role: CodeRole,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn sarif_report() {
        insta::assert_snapshot!(render(&scan()));
    }

    #[test]
    fn every_result_points_at_its_rule_descriptor() {
        let log: serde_json::Value = serde_json::from_str(&render(&scan())).unwrap();
        let run = &log["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        for result in run["results"].as_array().unwrap() {
            let index = result["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[index]["id"], result["ruleId"]);
        }
        assert_eq!(rules.len(), 4);
    }

    #[test]
    fn only_findings_with_a_fix_carry_fixes() {
        let log: serde_json::Value = serde_json::from_str(&render(&scan())).unwrap();
        let with_fixes: Vec<_> = log["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r.get("fixes").is_some())
            .map(|r| r["ruleId"].as_str().unwrap())
            .collect();
        assert_eq!(with_fixes, ["jvm.jca.aes-128"]);
    }
}
