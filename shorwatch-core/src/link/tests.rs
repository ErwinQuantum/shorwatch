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
            receiver_call: None,
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

/// A production helper `com.acme.Util.sign(alg)` whose `getInstance(alg)`
/// waits for its callers, and a caller in `caller` with the given role.
fn helper_and_caller(caller_role: CodeRole) -> Vec<SourceUnit> {
    use crate::ir::{Candidate, TypeRef};
    let mut helper = SourceUnit::new("Util.java", Language::Java);
    helper.push(
        FactKind::Call {
            receiver: Some(TypeRef::qualified("java.security.Signature")),
            method: "getInstance".into(),
            args: vec![Arg {
                value: ArgValue::OneOf(vec![Candidate {
                    value: ArgValue::Param {
                        owner: "com.acme.Util".into(),
                        method: "sign".into(),
                        arity: 1,
                        index: 0,
                        param: "alg".into(),
                    },
                    flow: vec![],
                }]),
                raw: "alg".into(),
                resolved_via: Some("alg".into()),
                location: Location::line(3, 9, 12),
            }],
            receiver_origin: None,
            receiver_call: None,
        },
        SourceUnit::ROOT,
        Location::line(3, 1, 13),
    );
    let mut caller = SourceUnit::new("Caller.java", Language::Java);
    caller.set_role(caller_role);
    caller.push(
        FactKind::Call {
            receiver: Some(TypeRef::qualified("com.acme.Util")),
            method: "sign".into(),
            args: vec![Arg::str("SHA1withRSA", Location::line(7, 18, 31))],
            receiver_origin: None,
            receiver_call: None,
        },
        SourceUnit::ROOT,
        Location::line(7, 9, 32),
    );
    vec![helper, caller]
}

fn helper_arg(units: &[SourceUnit]) -> &Arg {
    match &units[0].facts()[0].kind {
        FactKind::Call { args, .. } => &args[0],
        _ => unreachable!(),
    }
}

#[test]
fn parameters_take_the_values_other_files_pass() {
    let mut units = helper_and_caller(CodeRole::Production);
    link(&mut units);
    let arg = helper_arg(&units);
    assert_eq!(arg.match_texts(), ["SHA1withRSA"]);
    let ArgValue::OneOf(candidates) = &arg.value else {
        panic!("{arg:?}")
    };
    let notes: Vec<_> = candidates[0]
        .flow
        .iter()
        .map(|s| (s.path.as_deref(), s.note.as_str()))
        .collect();
    assert_eq!(
        notes,
        [
            (Some("Caller.java"), "\"SHA1withRSA\" is written here"),
            (Some("Caller.java"), "passed as alg to sign(...)"),
        ]
    );
}

#[test]
fn production_code_takes_no_values_from_test_code() {
    let mut units = helper_and_caller(CodeRole::Test);
    link(&mut units);
    assert_eq!(helper_arg(&units).value, ArgValue::Unknown);
}
