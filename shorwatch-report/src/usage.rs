//! How a finding says what its algorithm is used for, in every report.

use shorwatch_core::{AgreementShape, Finding};

/// The shape worth saying: `undetermined` is the common case and says
/// nothing the usage does not.
pub(crate) fn stated_shape(finding: &Finding) -> Option<AgreementShape> {
    finding
        .shape
        .filter(|shape| *shape != AgreementShape::Undetermined)
}

/// `key-agreement (ephemeral-static)`, or the usage alone.
pub(crate) fn usage_with_shape(finding: &Finding) -> Option<String> {
    let usage = finding.usage?;
    Some(match stated_shape(finding) {
        Some(shape) => format!("{usage} ({shape})"),
        None => usage.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn every_format_says_the_shape_a_finding_has() {
        use crate::terminal::{Options, View};
        let mut scan = scan();
        let finding = &mut scan.findings[0];
        finding.usage = Some(shorwatch_core::Usage::KeyAgreement);
        finding.shape = Some(AgreementShape::EphemeralStatic);
        let rule = finding.rule_id.clone();

        let details = crate::terminal::render(
            &scan,
            &Options {
                view: View::Details,
                ..Options::default()
            },
        );
        assert!(
            anstream::adapter::strip_str(&details)
                .to_string()
                .contains("key-agreement · ephemeral-static")
        );

        assert!(crate::markdown::render(&scan).contains("key-agreement (ephemeral-static)"));

        let sarif: serde_json::Value = serde_json::from_str(&crate::sarif::render(&scan)).unwrap();
        let result = sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["ruleId"] == rule.as_str() && r["properties"]["shape"] == "ephemeral-static"
            })
            .unwrap();
        assert!(
            result["properties"]["tags"]
                .as_array()
                .unwrap()
                .contains(&"shape:ephemeral-static".into())
        );
        assert!(
            result["message"]["text"]
                .as_str()
                .unwrap()
                .contains("Used for: key-agreement (ephemeral-static).")
        );

        let cbom = crate::cbom::render(&scan);
        assert!(cbom.contains("ephemeral-static)"), "{cbom}");

        let json: serde_json::Value = serde_json::from_str(&crate::json::render(&scan)).unwrap();
        assert_eq!(json["findings"][0]["shape"], "ephemeral-static");
    }

    #[test]
    fn the_shape_is_said_only_when_it_is_known() {
        let mut finding = scan().findings.remove(0);
        finding.usage = Some(shorwatch_core::Usage::KeyAgreement);
        finding.shape = Some(AgreementShape::Undetermined);
        assert_eq!(usage_with_shape(&finding).as_deref(), Some("key-agreement"));
        finding.shape = Some(AgreementShape::EphemeralStatic);
        assert_eq!(
            usage_with_shape(&finding).as_deref(),
            Some("key-agreement (ephemeral-static)")
        );
        finding.usage = None;
        assert_eq!(usage_with_shape(&finding), None);
    }
}
