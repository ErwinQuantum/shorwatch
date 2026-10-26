//! Rule validation tests, plus `rsa_rule()`, a fixture shared with the
//! engine tests.

use super::*;
use crate::ir::{Platform, ScopeKind};

pub(crate) fn rsa_rule() -> Rule {
    Rule {
        id: "jvm.jca.rsa".into(),
        platform: Platform::Jvm,
        algorithm: "RSA".into(),
        category: Category::Shor,
        severity: Severity::High,
        title: "RSA is broken by Shor's algorithm".into(),
        message: "RSA usage detected.".into(),
        suggestion: "Migrate to ML-KEM / ML-DSA.".into(),
        references: vec![Reference {
            title: "FIPS 203".into(),
            url: "https://csrc.nist.gov/pubs/fips/203/final".into(),
        }],
        patterns: vec![
            Pattern::Call {
                receiver: "java.security.KeyPairGenerator".into(),
                method: "getInstance".into(),
                arg: Some(ArgPattern {
                    index: 0,
                    matches: "(?i)^RSA$".into(),
                }),
                origin: None,
            },
            Pattern::Construct {
                ty: "org.bouncycastle.crypto.engines.RSAEngine".into(),
                arg: None,
            },
        ],
        hybrid: Some(HybridSpec {
            scope: ScopeKind::Type,
            markers: vec![
                Marker::Import(r"^org\.bouncycastle\.pqc\.".into()),
                Marker::Literal("(?i)kyber|ml-?kem".into()),
            ],
        }),
        fix: None,
        crypto: None,
    }
}

fn fix() -> FixSpec {
    FixSpec {
        description: "use a bigger key".into(),
        replace: "128".into(),
        with: "256".into(),
    }
}

#[test]
fn compiles_a_valid_rule() {
    let set = RuleSet::compile([rsa_rule()]).unwrap();
    assert_eq!(set.len(), 1);
}

#[test]
fn shor_rules_cannot_carry_a_fix() {
    let rule = Rule {
        fix: Some(fix()),
        ..rsa_rule()
    };
    assert_eq!(
        RuleSet::compile([rule]).unwrap_err(),
        RuleError::FixNotAllowed("jvm.jca.rsa".into())
    );
}

#[test]
fn grover_rules_may_carry_a_fix() {
    let rule = Rule {
        category: Category::Grover,
        fix: Some(fix()),
        ..rsa_rule()
    };
    assert!(RuleSet::compile([rule]).is_ok());
}

#[test]
fn fix_requires_an_argument_to_rewrite() {
    let rule = Rule {
        category: Category::Grover,
        fix: Some(fix()),
        patterns: vec![Pattern::Construct {
            ty: "a.B".into(),
            arg: None,
        }],
        ..rsa_rule()
    };
    assert_eq!(
        RuleSet::compile([rule]).unwrap_err(),
        RuleError::FixWithoutArg("jvm.jca.rsa".into())
    );
}

#[test]
fn rejects_duplicate_ids() {
    let err = RuleSet::compile([rsa_rule(), rsa_rule()]).unwrap_err();
    assert_eq!(err, RuleError::DuplicateId("jvm.jca.rsa".into()));
}

#[test]
fn rejects_invalid_regex() {
    let mut rule = rsa_rule();
    rule.hybrid
        .as_mut()
        .unwrap()
        .markers
        .push(Marker::Type("(".into()));
    assert!(matches!(
        RuleSet::compile([rule]),
        Err(RuleError::InvalidRegex { .. })
    ));
}

#[test]
fn rejects_rules_without_references() {
    let rule = Rule {
        references: vec![],
        ..rsa_rule()
    };
    assert!(matches!(
        RuleSet::compile([rule]),
        Err(RuleError::Empty {
            field: "references",
            ..
        })
    ));
}
