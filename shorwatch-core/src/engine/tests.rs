//! Engine tests on hand-built units.

use crate::finding::Status;
use crate::ir::{Arg, FactKind, Language, Location, ScopeKind, TypeRef};
use crate::rule::tests::rsa_rule;
use crate::rule::{ArgPattern, Category, FixSpec, Pattern, Rule, RuleSet};

use super::*;

fn loc(line: u32) -> Location {
    Location::line(line, 1, 40)
}

fn get_instance(unit: &mut SourceUnit, scope: crate::ir::ScopeId, ty: &str, alg: &str, line: u32) {
    unit.push(
        FactKind::Call {
            receiver: Some(TypeRef::qualified(ty)),
            method: "getInstance".into(),
            args: vec![Arg::str(alg, loc(line))],
            receiver_origin: None,
            receiver_call: None,
            chain: Vec::new(),
        },
        scope,
        loc(line),
    );
}

fn rules() -> RuleSet {
    RuleSet::compile([rsa_rule()]).unwrap()
}

/// File with `class A { void run() { ... } }` and no facts yet.
fn unit_with_method() -> (SourceUnit, crate::ir::ScopeId, crate::ir::ScopeId) {
    let mut unit = SourceUnit::new("A.java", Language::Java);
    let class = unit.add_scope(ScopeKind::Type, Some("A".into()), SourceUnit::ROOT);
    let method = unit.add_scope(ScopeKind::Method, Some("run".into()), class);
    (unit, class, method)
}

#[test]
fn detects_rsa_key_pair_generator() {
    let (mut unit, _, method) = unit_with_method();
    get_instance(
        &mut unit,
        method,
        "java.security.KeyPairGenerator",
        "RSA",
        3,
    );

    let findings = analyze(&unit, &rules());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "jvm.jca.rsa");
    assert_eq!(findings[0].status, Status::Vulnerable);
    assert_eq!(findings[0].location.start.line, 3);
    assert!(findings[0].fix.is_none());
}

#[test]
fn argument_must_match() {
    let (mut unit, _, method) = unit_with_method();
    get_instance(
        &mut unit,
        method,
        "java.security.KeyPairGenerator",
        "ML-KEM",
        3,
    );
    assert!(analyze(&unit, &rules()).is_empty());
}

#[test]
fn receiver_type_must_match() {
    let (mut unit, _, method) = unit_with_method();
    get_instance(&mut unit, method, "com.acme.KeyPairGenerator", "RSA", 3);
    assert!(analyze(&unit, &rules()).is_empty());
}

#[test]
fn unknown_argument_value_does_not_match() {
    let (mut unit, _, method) = unit_with_method();
    unit.push(
        FactKind::Call {
            receiver: Some(TypeRef::simple("KeyPairGenerator")),
            method: "getInstance".into(),
            args: vec![Arg {
                value: crate::ir::ArgValue::Unknown,
                raw: "alg()".into(),
                resolved_via: None,
                location: loc(3),
            }],
            receiver_origin: None,
            receiver_call: None,
            chain: Vec::new(),
        },
        method,
        loc(3),
    );
    assert!(analyze(&unit, &rules()).is_empty());
}

#[test]
fn detects_constructor_pattern() {
    let (mut unit, _, method) = unit_with_method();
    unit.push(
        FactKind::Construct {
            ty: TypeRef::qualified("org.bouncycastle.crypto.engines.RSAEngine"),
            args: vec![],
        },
        method,
        loc(5),
    );
    assert_eq!(analyze(&unit, &rules()).len(), 1);
}

#[test]
fn pqc_literal_in_same_class_marks_in_transition() {
    let (mut unit, class, method) = unit_with_method();
    let other = unit.add_scope(ScopeKind::Method, Some("kem".into()), class);
    get_instance(
        &mut unit,
        method,
        "java.security.KeyPairGenerator",
        "RSA",
        3,
    );
    unit.push(
        FactKind::Literal {
            value: "ML-KEM-768".into(),
            calls: Vec::new(),
        },
        other,
        loc(8),
    );

    let findings = analyze(&unit, &rules());
    assert_eq!(findings[0].status, Status::InTransition);
    assert_eq!(
        findings[0].hybrid_evidence.as_ref().unwrap().text,
        "ML-KEM-768"
    );
}

#[test]
fn pqc_literal_in_another_class_does_not_count() {
    let (mut unit, _, method) = unit_with_method();
    let other_class = unit.add_scope(ScopeKind::Type, Some("B".into()), SourceUnit::ROOT);
    get_instance(
        &mut unit,
        method,
        "java.security.KeyPairGenerator",
        "RSA",
        3,
    );
    unit.push(
        FactKind::Literal {
            value: "Kyber".into(),
            calls: Vec::new(),
        },
        other_class,
        loc(12),
    );

    assert_eq!(analyze(&unit, &rules())[0].status, Status::Vulnerable);
}

#[test]
fn pqc_import_counts_for_the_whole_file() {
    let (mut unit, _, method) = unit_with_method();
    unit.push(
        FactKind::Import {
            path: "org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator".into(),
        },
        SourceUnit::ROOT,
        loc(1),
    );
    get_instance(
        &mut unit,
        method,
        "java.security.KeyPairGenerator",
        "RSA",
        3,
    );

    assert_eq!(analyze(&unit, &rules())[0].status, Status::InTransition);
}

fn aes_rule() -> Rule {
    Rule {
        id: "jvm.jca.aes-128".into(),
        algorithm: "AES-128".into(),
        category: Category::Grover,
        patterns: vec![Pattern::Call {
            receiver: "javax.crypto.KeyGenerator".into(),
            method: "init".into(),
            arg: Some(ArgPattern {
                index: 0,
                matches: "^128$".into(),
            }),
            with_arg: None,
            origin: Some(ArgPattern {
                index: 0,
                matches: "(?i)^AES".into(),
            }),
            unless_chain: None,
        }],
        hybrid: None,
        fix: Some(FixSpec {
            description: "Use a 256-bit key".into(),
            replace: "^128$".into(),
            with: "256".into(),
        }),
        ..rsa_rule()
    }
}

fn key_generator_init(arg: Arg) -> SourceUnit {
    key_generator_init_from(arg, None)
}

/// `generator.init(arg)`, `generator` created by a factory called with `origin`.
fn key_generator_init_from(arg: Arg, origin: Option<Vec<Arg>>) -> SourceUnit {
    let (mut unit, _, method) = unit_with_method();
    unit.push(
        FactKind::Call {
            receiver: Some(TypeRef::simple("KeyGenerator")),
            method: "init".into(),
            args: vec![arg],
            receiver_origin: origin,
            receiver_call: None,
            chain: Vec::new(),
        },
        method,
        loc(4),
    );
    unit
}

#[test]
fn grover_fix_rewrites_the_matched_argument() {
    let arg_loc = Location::line(4, 12, 15);
    let unit = key_generator_init(Arg::int(128, arg_loc));
    let set = RuleSet::compile([aes_rule()]).unwrap();

    let fix = analyze(&unit, &set).remove(0).fix.unwrap();
    assert_eq!(fix.replacement, "256");
    assert_eq!(fix.location, arg_loc);
}

#[test]
fn no_fix_when_value_comes_from_a_constant() {
    let unit = key_generator_init(Arg {
        resolved_via: Some("KEY_BITS".into()),
        raw: "KEY_BITS".into(),
        ..Arg::int(128, loc(4))
    });
    let set = RuleSet::compile([aes_rule()]).unwrap();

    let findings = analyze(&unit, &set);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].fix.is_none());
}

fn jws_rule(matches: Option<&str>) -> Rule {
    Rule {
        id: "jvm.nimbus.jose-rsa".into(),
        patterns: vec![Pattern::Field {
            owner: "com.nimbusds.jose.JWSAlgorithm".into(),
            matches: matches.map(str::to_owned),
        }],
        ..rsa_rule()
    }
}

fn field(unit: &mut SourceUnit, scope: crate::ir::ScopeId, owner: TypeRef, name: &str) {
    unit.push(
        FactKind::Field {
            owner,
            name: name.into(),
        },
        scope,
        loc(4),
    );
}

#[test]
fn field_pattern_matches_owner_and_name() {
    let (mut unit, _, method) = unit_with_method();
    let jws = TypeRef::qualified("com.nimbusds.jose.JWSAlgorithm");
    field(&mut unit, method, jws.clone(), "RS256");
    field(&mut unit, method, jws, "HS256");
    let set = RuleSet::compile([jws_rule(Some("^(RS|PS)[0-9]+$"))]).unwrap();

    let findings = analyze(&unit, &set);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].fix.is_none());
}

#[test]
fn field_pattern_requires_the_owner_type() {
    let (mut unit, _, method) = unit_with_method();
    field(
        &mut unit,
        method,
        TypeRef::qualified("com.acme.JWSAlgorithm"),
        "RS256",
    );
    let set = RuleSet::compile([jws_rule(Some("^RS256$"))]).unwrap();
    assert!(analyze(&unit, &set).is_empty());
}

#[test]
fn field_pattern_without_name_matches_any_field() {
    let (mut unit, _, method) = unit_with_method();
    field(&mut unit, method, TypeRef::simple("JWSAlgorithm"), "ES256K");
    let set = RuleSet::compile([jws_rule(None)]).unwrap();
    assert_eq!(analyze(&unit, &set).len(), 1);
}

#[test]
fn literal_pattern_matches_string_literals_anywhere() {
    let (mut unit, _, method) = unit_with_method();
    for value in [
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_AES_256_GCM_SHA384",
    ] {
        unit.push(
            FactKind::Literal {
                value: value.into(),
                calls: Vec::new(),
            },
            method,
            loc(4),
        );
    }
    let rule = Rule {
        id: "jvm.tls.tls-key-exchange".into(),
        patterns: vec![Pattern::Literal {
            matches: "^TLS_(RSA|DHE?|ECDHE?)_".into(),
            unless_call: None,
            in_call: None,
        }],
        ..rsa_rule()
    };
    let set = RuleSet::compile([rule]).unwrap();
    assert_eq!(analyze(&unit, &set).len(), 1);
}

#[test]
fn literal_pattern_skips_literals_passed_to_excluded_calls() {
    let (mut unit, _, method) = unit_with_method();
    for calls in [
        vec!["setIncludeCipherSuites"],
        vec!["of", "setExcludeCipherSuites"],
    ] {
        unit.push(
            FactKind::Literal {
                value: "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
                calls: calls.into_iter().map(str::to_owned).collect(),
            },
            method,
            loc(4),
        );
    }
    let rule = Rule {
        id: "jvm.tls.tls-key-exchange".into(),
        patterns: vec![Pattern::Literal {
            matches: "^TLS_RSA_".into(),
            unless_call: Some("(?i)exclude".into()),
            in_call: None,
        }],
        ..rsa_rule()
    };
    let set = RuleSet::compile([rule]).unwrap();
    assert_eq!(analyze(&unit, &set).len(), 1);
}

#[test]
fn pqc_field_owner_is_hybrid_evidence() {
    let (mut unit, _, method) = unit_with_method();
    get_instance(
        &mut unit,
        method,
        "java.security.Signature",
        "SHA256withRSA",
        3,
    );
    field(
        &mut unit,
        method,
        TypeRef::qualified("org.bouncycastle.jcajce.spec.MLDSAParameterSpec"),
        "ml_dsa_65",
    );
    let mut rule = rsa_rule();
    rule.patterns.push(Pattern::Call {
        receiver: "java.security.Signature".into(),
        method: "getInstance".into(),
        arg: None,
        with_arg: None,
        origin: None,
        unless_chain: None,
    });
    rule.hybrid.as_mut().unwrap().markers = vec![crate::rule::Marker::Type("(?i)ml-?dsa".into())];
    let set = RuleSet::compile([rule]).unwrap();

    assert_eq!(analyze(&unit, &set)[0].status, Status::InTransition);
}

#[test]
fn findings_are_sorted_by_position() {
    let (mut unit, _, method) = unit_with_method();
    get_instance(
        &mut unit,
        method,
        "java.security.KeyPairGenerator",
        "RSA",
        9,
    );
    get_instance(
        &mut unit,
        method,
        "java.security.KeyPairGenerator",
        "RSA",
        2,
    );

    let lines: Vec<_> = analyze(&unit, &rules())
        .iter()
        .map(|f| f.location.start.line)
        .collect();
    assert_eq!(lines, [2, 9]);
}

#[test]
fn receiver_origin_tells_aes_from_hmac_key_generators() {
    let set = RuleSet::compile([aes_rule()]).unwrap();
    let found = |origin: Option<Vec<Arg>>| {
        analyze(
            &key_generator_init_from(Arg::int(128, loc(4)), origin),
            &set,
        )
        .len()
    };
    let unknown = Arg {
        value: crate::ir::ArgValue::Unknown,
        raw: "configured".into(),
        resolved_via: None,
        location: loc(2),
    };
    assert_eq!(found(Some(vec![Arg::str("AES", loc(2))])), 1);
    assert_eq!(found(Some(vec![Arg::str("HmacSHA256", loc(2))])), 0);
    // Unknown origins keep the finding: better a false positive than a miss.
    assert_eq!(found(None), 1);
    assert_eq!(found(Some(vec![unknown])), 1);
}

#[test]
fn a_rule_reports_a_line_once() {
    // Two RSA names on one line: one thing to fix, one finding. The same
    // rule on another line still reports.
    let (mut unit, _, method) = unit_with_method();
    for (alg, line) in [("RSA", 3), ("RSA", 3), ("RSA", 4)] {
        get_instance(
            &mut unit,
            method,
            "java.security.KeyPairGenerator",
            alg,
            line,
        );
    }
    let lines: Vec<_> = analyze(&unit, &rules())
        .iter()
        .map(|f| f.location.start.line)
        .collect();
    assert_eq!(lines, [3, 4]);
}

#[test]
fn unless_chain_skips_a_call_followed_by_a_choice() {
    let call = |chain: &[&str]| {
        let (mut unit, _, method) = unit_with_method();
        unit.push(
            FactKind::Call {
                receiver: Some(TypeRef::qualified("org.x.Decoder")),
                method: "withUri".into(),
                args: vec![],
                receiver_origin: None,
                receiver_call: None,
                chain: chain.iter().map(|s| (*s).to_owned()).collect(),
            },
            method,
            loc(3),
        );
        unit
    };
    let mut rule = rsa_rule();
    rule.patterns = vec![Pattern::Call {
        receiver: "org.x.Decoder".into(),
        method: "withUri".into(),
        arg: None,
        with_arg: None,
        origin: None,
        unless_chain: Some("^algorithm$".into()),
    }];
    let rules = RuleSet::compile([rule]).unwrap();
    assert_eq!(analyze(&call(&["build"]), &rules).len(), 1);
    assert!(analyze(&call(&["algorithm", "build"]), &rules).is_empty());
}

#[test]
fn unless_property_skips_an_entry_another_one_overrides() {
    let config = |keys: &[&str]| {
        let mut unit = SourceUnit::new("application.yml", Language::Yaml);
        for (line, key) in (1..).zip(keys) {
            unit.push(
                FactKind::Property {
                    key: (*key).to_owned(),
                    value: "x".into(),
                },
                SourceUnit::ROOT,
                loc(line),
            );
        }
        unit
    };
    let mut rule = rsa_rule();
    rule.platform = crate::ir::Platform::Config;
    rule.patterns = vec![Pattern::Property {
        key: r"^jwt\.jwk-set-uri$".into(),
        matches: None,
        unless_property: Some(r"^jwt\.jws-algorithms".into()),
    }];
    let rules = RuleSet::compile([rule]).unwrap();
    assert_eq!(analyze(&config(&["jwt.jwk-set-uri"]), &rules).len(), 1);
    assert!(
        analyze(
            &config(&["jwt.jwk-set-uri", "jwt.jws-algorithms[0]"]),
            &rules
        )
        .is_empty()
    );
}

#[test]
fn literal_pattern_can_require_the_call_it_is_passed_to() {
    let (mut unit, _, method) = unit_with_method();
    for calls in [vec!["setNamedGroups"], vec!["println"]] {
        unit.push(
            FactKind::Literal {
                value: "secp256r1".into(),
                calls: calls.into_iter().map(str::to_owned).collect(),
            },
            method,
            loc(4),
        );
    }
    let rule = Rule {
        id: "jvm.tls.tls-key-exchange".into(),
        patterns: vec![Pattern::Literal {
            matches: "^secp256r1$".into(),
            unless_call: None,
            in_call: Some("^setNamedGroups$".into()),
        }],
        ..rsa_rule()
    };
    let set = RuleSet::compile([rule]).unwrap();
    assert_eq!(analyze(&unit, &set).len(), 1);
}

#[test]
fn call_pattern_can_constrain_two_arguments() {
    let (mut unit, _, method) = unit_with_method();
    for (key, value) in [
        ("jdk.tls.namedGroups", "x25519"),
        ("other.setting", "x25519"),
    ] {
        unit.push(
            FactKind::Call {
                receiver: Some(TypeRef::qualified("java.lang.System")),
                method: "setProperty".into(),
                args: vec![Arg::str(key, loc(5)), Arg::str(value, loc(5))],
                receiver_origin: None,
                receiver_call: None,
                chain: Vec::new(),
            },
            method,
            loc(5),
        );
    }
    let rule = Rule {
        id: "jvm.tls.tls-key-exchange".into(),
        patterns: vec![Pattern::Call {
            receiver: "java.lang.System".into(),
            method: "setProperty".into(),
            arg: Some(ArgPattern {
                index: 1,
                matches: "^x25519$".into(),
            }),
            with_arg: Some(ArgPattern {
                index: 0,
                matches: "^jdk[.]tls[.]namedGroups$".into(),
            }),
            origin: None,
            unless_chain: None,
        }],
        ..rsa_rule()
    };
    let set = RuleSet::compile([rule]).unwrap();
    assert_eq!(analyze(&unit, &set).len(), 1);
}
