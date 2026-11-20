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
                with_arg: None,
                origin: None,
                unless_chain: None,
                usage: Some(Usage::KeyGeneration),
            },
            Pattern::Construct {
                ty: "org.bouncycastle.crypto.engines.RSAEngine".into(),
                arg: None,
                usage: None,
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
        usage: Some(crate::rule::Usage::Unknown),
        suggestions: BTreeMap::new(),
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
fn a_shor_rule_that_says_nothing_about_its_usage_still_loads() {
    // Rules written by others predate the field: they are `unknown`, which
    // claims nothing, not an error.
    let rule = Rule {
        usage: None,
        ..rsa_rule()
    };
    assert!(RuleSet::compile([rule]).is_ok());
}

#[test]
fn a_pattern_may_state_its_own_usage_instead_of_the_rules() {
    let mut rule = Rule {
        usage: None,
        ..rsa_rule()
    };
    if let Pattern::Construct { usage, .. } = &mut rule.patterns[1] {
        *usage = Some(Usage::Unknown);
    }
    assert!(RuleSet::compile([rule]).is_ok());
}

#[test]
fn grover_rules_need_no_usage() {
    let rule = Rule {
        category: Category::Grover,
        usage: None,
        patterns: vec![Pattern::Construct {
            ty: "a.B".into(),
            arg: None,
            usage: None,
        }],
        ..rsa_rule()
    };
    assert!(RuleSet::compile([rule]).is_ok());
}

#[test]
fn references_must_be_web_links() {
    let mut rule = rsa_rule();
    rule.references[0].url = "javascript:alert(1)".into();
    assert_eq!(
        RuleSet::compile([rule]).unwrap_err(),
        RuleError::ReferenceNotHttp("jvm.jca.rsa".into(), "javascript:alert(1)".into())
    );
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
            usage: None,
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

#[test]
fn advice_per_usage_is_for_shor_rules_and_never_empty() {
    let grover = Rule {
        category: Category::Grover,
        suggestions: BTreeMap::from([(Usage::Signature, "x".to_owned())]),
        usage: None,
        ..rsa_rule()
    };
    assert_eq!(
        RuleSet::compile([grover]).unwrap_err(),
        RuleError::SuggestionsNotAllowed("jvm.jca.rsa".into())
    );
    let empty = Rule {
        suggestions: BTreeMap::from([(Usage::Signature, " ".to_owned())]),
        ..rsa_rule()
    };
    assert_eq!(
        RuleSet::compile([empty]).unwrap_err(),
        RuleError::Empty {
            id: "jvm.jca.rsa".into(),
            field: "suggestions"
        }
    );
}

#[test]
fn a_note_needs_text_platforms_and_something_to_look_for() {
    let valid = || Note {
        id: "tls".into(),
        platforms: vec![Platform::Jvm],
        topic: "TLS".into(),
        text: "Decided at run time.".into(),
        uses: vec![Pattern::Literal {
            matches: "x".into(),
            unless_call: None,
            in_call: None,
            usage: None,
        }],
        settings: vec![],
    };
    assert!(NoteSet::compile([valid()]).is_ok());
    for (note, field) in [
        (
            Note {
                text: " ".into(),
                ..valid()
            },
            "text",
        ),
        (
            Note {
                platforms: vec![],
                ..valid()
            },
            "platforms",
        ),
        (
            Note {
                uses: vec![],
                ..valid()
            },
            "uses or settings",
        ),
    ] {
        assert_eq!(
            NoteSet::compile([note]).unwrap_err(),
            RuleError::Empty {
                id: "tls".into(),
                field
            }
        );
    }
    assert_eq!(
        NoteSet::compile([valid(), valid()]).unwrap_err(),
        RuleError::DuplicateId("tls".into())
    );
}
