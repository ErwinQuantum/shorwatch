use super::*;
use crate::ir::{Arg, ArgValue, CodeRole, FactKind, Language, Location};

fn config(path: &str, entries: &[(&str, &str)]) -> SourceUnit {
    let mut unit = SourceUnit::new(path, Language::Yaml);
    for (key, value) in entries {
        unit.push(
            FactKind::Property {
                key: (*key).into(),
                value: (*value).into(),
            },
            SourceUnit::ROOT,
            Location::line(1, 1, 2),
        );
    }
    unit
}

fn java_with_injected(key: &str, default: Option<&str>) -> SourceUnit {
    let mut unit = SourceUnit::new("A.java", Language::Java);
    unit.push(
        FactKind::Call {
            receiver: None,
            method: "parse".into(),
            args: vec![Arg {
                value: ArgValue::Injected {
                    key: key.into(),
                    default: default.map(str::to_owned),
                    resolved: vec![],
                },
                raw: "alg".into(),
                resolved_via: Some(format!("${{{key}}}")),
                location: Location::line(3, 1, 4),
            }],
            receiver_origin: None,
        },
        SourceUnit::ROOT,
        Location::line(3, 1, 10),
    );
    unit
}

fn texts(unit: &SourceUnit) -> Vec<String> {
    match &unit.facts()[0].kind {
        FactKind::Call { args, .. } => args[0].match_texts(),
        _ => unreachable!(),
    }
}

#[test]
fn resolves_injected_values_from_config_units() {
    let mut units = vec![
        java_with_injected("jwt.algorithm", None),
        config("application.yml", &[("jwt.algorithm", "RS256")]),
    ];
    link(&mut units);
    assert_eq!(texts(&units[0]), ["RS256"]);
}

#[test]
fn keys_bind_relaxed() {
    let mut units = vec![
        java_with_injected("jwt.signingAlgorithm", None),
        config(
            "application.properties",
            &[("jwt.signing-algorithm", "ES256")],
        ),
    ];
    link(&mut units);
    assert_eq!(texts(&units[0]), ["ES256"]);
}

#[test]
fn every_profile_value_is_a_candidate() {
    let mut units = vec![
        java_with_injected("jwt.algorithm", Some("HS256")),
        config("application.yml", &[("jwt.algorithm", "HS256")]),
        config("application-prod.yml", &[("jwt.algorithm", "RS256")]),
    ];
    link(&mut units);
    assert_eq!(texts(&units[0]), ["HS256", "RS256"]);
}

#[test]
fn list_keys_collect_their_elements() {
    let mut units = vec![
        java_with_injected("security.algorithms", None),
        config(
            "application.yml",
            &[
                ("security.algorithms[0]", "ES256"),
                ("security.algorithms[1]", "RS256"),
            ],
        ),
    ];
    link(&mut units);
    assert_eq!(texts(&units[0]), ["ES256", "RS256"]);
}

#[test]
fn falls_back_to_the_default_when_unset() {
    let mut units = vec![
        java_with_injected("jwt.algorithm", Some("RS256")),
        config("application.yml", &[("server.port", "8080")]),
    ];
    link(&mut units);
    assert_eq!(texts(&units[0]), ["RS256"]);
}

#[test]
fn test_config_only_reaches_test_code() {
    let test_config = || {
        let mut unit = config(
            "src/test/resources/application.yml",
            &[("jwt.algorithm", "RS256")],
        );
        unit.set_role(CodeRole::Test);
        unit
    };
    let mut test_code = java_with_injected("jwt.algorithm", None);
    test_code.set_role(CodeRole::Test);
    let mut units = vec![
        java_with_injected("jwt.algorithm", None),
        test_code,
        config(
            "src/main/resources/application.yml",
            &[("jwt.algorithm", "HS256")],
        ),
        test_config(),
    ];
    link(&mut units);
    assert_eq!(texts(&units[0]), ["HS256"]);
    assert_eq!(texts(&units[1]), ["HS256", "RS256"]);
}

#[test]
fn unresolved_without_default_matches_nothing() {
    let mut units = vec![java_with_injected("jwt.algorithm", None)];
    link(&mut units);
    assert!(texts(&units[0]).is_empty());
}
