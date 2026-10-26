//! A Cryptography Bill of Materials: CycloneDX 1.6 with `cryptographic-asset`
//! components, the format of the PQCA ecosystem (CBOMkit and friends).
//!
//! Where SARIF lists *problems to fix*, a CBOM is an *inventory*: one
//! component per algorithm, with its primitive and NIST quantum security level,
//! and every place it occurs as evidence. Shorwatch only reports
//! quantum-vulnerable algorithms, so the inventory covers those; quantum-safe
//! crypto in the project is not listed (yet).
//!
//! The output is deterministic (no timestamp, no random serial number), so
//! the same code always yields the same CBOM.

use serde::Serialize;
use shorwatch_core::{Category, CodeRole, CryptoProperties, Finding, Severity, Status};

use crate::Scan;
use crate::summary::severity_label;

pub fn render(scan: &Scan) -> String {
    let bom = Bom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        version: 1,
        metadata: Metadata {
            tools: Tools {
                components: [Tool {
                    kind: "application",
                    name: "shorwatch",
                    version: &scan.tool_version,
                }],
            },
        },
        components: components(&scan.findings),
    };
    // Plain data with string keys: serialization cannot fail.
    serde_json::to_string_pretty(&bom).expect("CBOM serializes") + "\n"
}

/// One component per algorithm, in order of first appearance.
fn components(findings: &[Finding]) -> Vec<Component<'_>> {
    let mut groups: Vec<(&str, Vec<&Finding>)> = Vec::new();
    for finding in findings {
        match groups
            .iter_mut()
            .find(|(name, _)| *name == finding.algorithm)
        {
            Some((_, group)) => group.push(finding),
            None => groups.push((&finding.algorithm, vec![finding])),
        }
    }
    groups
        .into_iter()
        .map(|(name, group)| component(name, &group))
        .collect()
}

fn component<'a>(name: &'a str, findings: &[&'a Finding]) -> Component<'a> {
    let first = findings[0];
    let worst_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let status = if findings.iter().any(|f| f.status == Status::Vulnerable) {
        "vulnerable"
    } else {
        "in_transition"
    };
    Component {
        kind: "cryptographic-asset",
        bom_ref: format!("crypto/algorithm/{}", slug(name)),
        name,
        crypto_properties: CbomCrypto {
            asset_type: "algorithm",
            algorithm_properties: first.crypto.as_ref().map(algorithm_properties),
        },
        evidence: Evidence {
            occurrences: findings
                .iter()
                .map(|f| Occurrence {
                    location: &f.path,
                    line: f.location.start.line,
                    additional_context: format!(
                        "{} ({}{})",
                        f.rule_id,
                        match f.status {
                            Status::Vulnerable => "vulnerable",
                            Status::InTransition => "in transition",
                        },
                        match f.role {
                            CodeRole::Production => "",
                            CodeRole::Test => ", test code",
                        }
                    ),
                })
                .collect(),
        },
        properties: vec![
            Property::new(
                "shorwatch:category",
                match first.category {
                    Category::Shor => "shor",
                    Category::Grover => "grover",
                },
            ),
            Property::new("shorwatch:severity", severity_label(worst_severity)),
            Property::new("shorwatch:status", status),
        ],
    }
}

fn algorithm_properties(crypto: &CryptoProperties) -> AlgorithmProperties<'_> {
    AlgorithmProperties {
        primitive: crypto.primitive,
        parameter_set_identifier: crypto.parameter_set.as_deref(),
        crypto_functions: &crypto.functions,
        classical_security_level: crypto.classical_security_level,
        nist_quantum_security_level: crypto.nist_quantum_security_level,
    }
}

/// `RSA (JOSE/JWT)` -> `rsa-jose-jwt`.
fn slug(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut out = String::new();
    for word in lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        if !out.is_empty() {
            out.push('-');
        }
        out.push_str(word);
    }
    out
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Bom<'a> {
    bom_format: &'static str,
    spec_version: &'static str,
    version: u32,
    metadata: Metadata<'a>,
    components: Vec<Component<'a>>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    tools: Tools<'a>,
}

#[derive(Serialize)]
struct Tools<'a> {
    components: [Tool<'a>; 1],
}

#[derive(Serialize)]
struct Tool<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    name: &'static str,
    version: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Component<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: &'a str,
    crypto_properties: CbomCrypto<'a>,
    evidence: Evidence<'a>,
    properties: Vec<Property>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CbomCrypto<'a> {
    asset_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm_properties: Option<AlgorithmProperties<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AlgorithmProperties<'a> {
    primitive: shorwatch_core::Primitive,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameter_set_identifier: Option<&'a str>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    crypto_functions: &'a [shorwatch_core::CryptoFunction],
    #[serde(skip_serializing_if = "Option::is_none")]
    classical_security_level: Option<u32>,
    nist_quantum_security_level: u8,
}

#[derive(Serialize)]
struct Evidence<'a> {
    occurrences: Vec<Occurrence<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Occurrence<'a> {
    location: &'a str,
    line: u32,
    additional_context: String,
}

#[derive(Serialize)]
struct Property {
    name: &'static str,
    value: &'static str,
}

impl Property {
    fn new(name: &'static str, value: &'static str) -> Self {
        Self { name, value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn cbom_report() {
        insta::assert_snapshot!(render(&scan()));
    }

    #[test]
    fn one_component_per_algorithm_with_every_occurrence() {
        let mut scan = scan();
        let mut again = scan.findings[0].clone();
        again.location.start.line = 42;
        scan.findings.push(again);
        let bom: serde_json::Value = serde_json::from_str(&render(&scan)).unwrap();
        let components = bom["components"].as_array().unwrap();
        let rsa: Vec<_> = components.iter().filter(|c| c["name"] == "RSA").collect();
        assert_eq!(rsa.len(), 1);
        // The fixture's RSA in production and in test code, plus the copy.
        assert_eq!(
            rsa[0]["evidence"]["occurrences"].as_array().unwrap().len(),
            3
        );
    }

    #[test]
    fn slugs_are_stable_identifiers() {
        assert_eq!(slug("RSA (JOSE/JWT)"), "rsa-jose-jwt");
        assert_eq!(slug("AES-128"), "aes-128");
    }
}
