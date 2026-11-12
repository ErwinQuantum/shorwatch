use super::*;
use crate::ir::{
    Arg, ArgValue, CallOwner, CallRef, CodeRole, FactKind, Language, Location, MethodSummary,
    TypeDecl, TypeRef,
};

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
            chain: Vec::new(),
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
    link(&mut units, &Library::default());
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
    link(&mut units, &Library::default());
    assert_eq!(texts(&units[0]), ["ES256"]);
}

#[test]
fn every_profile_value_is_a_candidate() {
    let mut units = vec![
        java_with_injected("jwt.algorithm", Some("HS256")),
        config("application.yml", &[("jwt.algorithm", "HS256")]),
        config("application-prod.yml", &[("jwt.algorithm", "RS256")]),
    ];
    link(&mut units, &Library::default());
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
    link(&mut units, &Library::default());
    assert_eq!(texts(&units[0]), ["ES256", "RS256"]);
}

#[test]
fn falls_back_to_the_default_when_unset() {
    let mut units = vec![
        java_with_injected("jwt.algorithm", Some("RS256")),
        config("application.yml", &[("server.port", "8080")]),
    ];
    link(&mut units, &Library::default());
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
    link(&mut units, &Library::default());
    assert_eq!(texts(&units[0]), ["HS256"]);
    assert_eq!(texts(&units[1]), ["HS256", "RS256"]);
}

#[test]
fn unresolved_without_default_matches_nothing() {
    let mut units = vec![java_with_injected("jwt.algorithm", None)];
    link(&mut units, &Library::default());
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
            chain: Vec::new(),
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
            chain: Vec::new(),
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
    link(&mut units, &Library::default());
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
    link(&mut units, &Library::default());
    assert_eq!(helper_arg(&units).value, ArgValue::Unknown);
}

/// `jsch.getSession(...).setConfig("kex", ...)`: the session's type is only
/// known from the library's compiled declarations.
fn session_call() -> SourceUnit {
    let mut unit = SourceUnit::new("Tunnel.kt", Language::Kotlin);
    unit.push(
        FactKind::Call {
            receiver: None,
            method: "setConfig".into(),
            args: vec![Arg::str("kex", Location::line(4, 9, 14))],
            receiver_origin: None,
            receiver_call: Some(CallRef {
                owner: CallOwner::Type(TypeRef::qualified("com.jcraft.jsch.JSch")),
                method: "getSession".into(),
                arity: 3,
            }),
            chain: Vec::new(),
        },
        SourceUnit::ROOT,
        Location::line(4, 1, 20),
    );
    unit
}

fn library_method(owner: &str, name: &str, arity: usize, returns: &str) -> MethodSummary {
    MethodSummary {
        owner: owner.into(),
        name: name.into(),
        arity,
        return_type: Some(TypeRef::qualified(returns)),
        returns: vec![],
    }
}

fn receiver(unit: &SourceUnit) -> Option<&str> {
    match &unit.facts()[0].kind {
        FactKind::Call { receiver, .. } => receiver.as_ref()?.qualified.as_deref(),
        _ => unreachable!(),
    }
}

#[test]
fn library_return_types_type_chained_receivers() {
    let mut units = vec![session_call()];
    link(&mut units, &Library::default());
    assert_eq!(receiver(&units[0]), None);

    // Declared by a superclass of JSch, as libraries often do.
    let library = Library {
        types: vec![
            TypeDecl {
                name: "com.jcraft.jsch.JSch".into(),
                supertypes: vec![TypeRef::qualified("com.jcraft.jsch.SessionFactory")],
            },
            TypeDecl {
                name: "com.jcraft.jsch.SessionFactory".into(),
                supertypes: vec![],
            },
        ],
        methods: vec![
            library_method(
                "com.jcraft.jsch.SessionFactory",
                "getSession",
                3,
                "com.jcraft.jsch.Session",
            ),
            library_method("com.other.Pool", "getSession", 3, "com.other.PooledSession"),
        ],
    };
    let mut units = vec![session_call()];
    link(&mut units, &library);
    assert_eq!(receiver(&units[0]), Some("com.jcraft.jsch.Session"));
}

#[test]
fn only_the_library_types_a_project_reaches_are_kept() {
    let units = vec![session_call()];
    let mut library = Library::default();
    for i in 0..1000 {
        library.types.push(TypeDecl {
            name: format!("com.big.Type{i}"),
            supertypes: vec![],
        });
        library.methods.push(library_method(
            &format!("com.big.Type{i}"),
            "get",
            0,
            "com.big.Type0",
        ));
    }
    library.types.push(TypeDecl {
        name: "com.jcraft.jsch.JSch".into(),
        supertypes: vec![],
    });
    library.methods.push(library_method(
        "com.jcraft.jsch.JSch",
        "getSession",
        3,
        "com.jcraft.jsch.Session",
    ));
    let relevant = library::relevant(&library, &units);
    let types: Vec<_> = relevant.types.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(types, ["com.jcraft.jsch.JSch"]);
    assert_eq!(relevant.methods.len(), 1);
}

#[test]
fn a_call_of_another_platform_passes_no_values() {
    // The same `Util.sign("SHA1withRSA")` call, written in C#: the Java
    // helper is not its callee.
    let mut units = helper_and_caller(CodeRole::Production);
    units[1] = {
        let java = std::mem::replace(&mut units[1], SourceUnit::new("", Language::Java));
        let mut csharp = SourceUnit::new("Caller.cs", Language::CSharp);
        for fact in java.facts() {
            csharp.push(fact.kind.clone(), SourceUnit::ROOT, fact.location);
        }
        csharp
    };
    link(&mut units, &Library::default());
    assert_eq!(helper_arg(&units).value, ArgValue::Unknown);
}

#[test]
fn linking_by_platform_keeps_the_units_in_place() {
    let mut units = helper_and_caller(CodeRole::Production);
    units.insert(1, config("application.yml", &[("a.b", "c")]));
    units.push(SourceUnit::new("Other.cs", Language::CSharp));
    let paths: Vec<_> = units.iter().map(|u| u.path().to_owned()).collect();
    link(&mut units, &Library::default());
    let after: Vec<_> = units.iter().map(|u| u.path().to_owned()).collect();
    assert_eq!(paths, after);
    assert_eq!(helper_arg(&units).match_texts(), ["SHA1withRSA"]);
}
