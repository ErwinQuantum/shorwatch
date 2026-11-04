//! Loader tests, plus integrity checks of the built-in rules (layout
//! convention, unused profiles, FIPS references).

use std::collections::BTreeSet;

use super::*;

const MINIMAL: &str = r#"
id: test.rule
platform: jvm
algorithm: X
category: shor
severity: low
title: t
message: m
suggestion: s
references: [{ title: r, url: "https://example.com" }]
patterns:
  - call: { type: a.B, method: c }
"#;

const PROFILE: &str = r#"
algorithm: X
category: shor
severity: high
title: t
message: m
suggestion: s
references: [{ title: r, url: "https://example.com" }]
hybrid: pqc
"#;

const MARKERS: &str = "scope: type\nmarkers:\n  - literal: 'ml-kem'\n";

fn catalog(files: &[(&str, &str)]) -> Catalog {
    let mut catalog = Catalog::default();
    for (path, yaml) in files {
        catalog.add(path, path, yaml).unwrap();
    }
    catalog
}

#[test]
fn builtin_rules_compile() {
    assert!(!builtin().unwrap().is_empty());
}

#[test]
fn rules_inherit_their_profile_and_markers() {
    let rule =
        "id: jvm.lib.x\nprofile: x\nplatform: jvm\npatterns:\n  - call: { type: a.B, method: c }\n";
    let catalog = catalog(&[
        ("algorithms/x.yaml", PROFILE),
        ("markers/pqc.yaml", MARKERS),
        ("jvm/lib/x.yaml", rule),
    ]);
    let rules = catalog.rules().unwrap();
    assert_eq!(rules[0].algorithm, "X");
    assert_eq!(rules[0].hybrid.as_ref().unwrap().markers.len(), 1);
}

#[test]
fn rule_fields_override_the_profile() {
    let rule = "id: r\nprofile: x\nplatform: jvm\nseverity: low\npatterns:\n  - call: { type: a.B, method: c }\n";
    let catalog = catalog(&[
        ("algorithms/x.yaml", PROFILE),
        ("markers/pqc.yaml", MARKERS),
        ("jvm/r.yaml", rule),
    ]);
    assert_eq!(
        catalog.rules().unwrap()[0].severity,
        shorwatch_core::Severity::Low
    );
}

#[test]
fn unknown_profile_is_an_error() {
    let rule = "id: r\nprofile: nope\nplatform: jvm\npatterns: []\n";
    let err = catalog(&[("jvm/r.yaml", rule)]).rules().unwrap_err();
    assert!(matches!(err, LoadError::UnknownProfile { profile, .. } if profile == "nope"));
}

#[test]
fn duplicate_profiles_are_rejected() {
    let mut catalog = catalog(&[("algorithms/x.yaml", PROFILE)]);
    let err = catalog
        .add("algorithms/x.yaml", "other", PROFILE)
        .unwrap_err();
    assert!(matches!(err, LoadError::Duplicate { name, .. } if name == "x"));
}

/// `jvm/nimbus/jose-rsa.yaml` must be `jvm.nimbus.jose-rsa`, target the
/// `jvm` platform and use the `jose-rsa` profile: the tree is the index.
#[test]
fn builtin_rules_follow_the_layout_convention() {
    let catalog = Catalog::builtin().unwrap();
    for source in &catalog.rules {
        let path = source.origin.strip_prefix("builtin:").unwrap();
        let path = path.trim_end_matches(".yaml");
        let get = |key: &str| source.doc.get(key).and_then(Value::as_str);
        assert_eq!(get("id"), Some(path.replace('/', ".").as_str()), "{path}");
        assert_eq!(get("platform"), path.split('/').next(), "{path}");
        assert_eq!(get("profile"), path.rsplit('/').next(), "{path}");
    }
}

#[test]
fn every_builtin_profile_and_marker_set_is_used() {
    let catalog = Catalog::builtin().unwrap();
    let used: BTreeSet<_> = catalog
        .rules
        .iter()
        .filter_map(|r| r.doc.get("profile").and_then(Value::as_str))
        .collect();
    let unused: Vec<_> = catalog
        .profiles
        .keys()
        .filter(|p| !used.contains(p.as_str()))
        .collect();
    assert!(unused.is_empty(), "unused profiles: {unused:?}");

    let used_markers: BTreeSet<_> = catalog
        .profiles
        .values()
        .filter_map(|p| p.doc.get("hybrid").and_then(Value::as_str))
        .collect();
    for name in catalog.markers.keys() {
        assert!(
            used_markers.contains(name.as_str()),
            "unused markers: {name}"
        );
    }
}

#[test]
fn shor_rules_point_to_a_pqc_standard() {
    for rule in builtin_rules().unwrap() {
        if rule.category == shorwatch_core::Category::Shor {
            assert!(
                rule.references
                    .iter()
                    .any(|r| r.url.contains("/fips/203/") || r.url.contains("/fips/204/")),
                "{} must reference FIPS 203 or FIPS 204",
                rule.id
            );
        }
    }
}

#[test]
fn parses_a_minimal_rule() {
    let rule = parse("test", MINIMAL).unwrap();
    assert_eq!(rule.id, "test.rule");
    assert!(rule.hybrid.is_none());
}

#[test]
fn parses_field_and_property_patterns() {
    let yaml = MINIMAL.replace(
        "  - call: { type: a.B, method: c }",
        "  - field: { type: a.B, matches: '^RS' }\n  - field: { type: a.C }\n  - property: { key: '^jwt\\.alg$', matches: '^RS' }",
    );
    let rule = parse("test", &yaml).unwrap();
    assert_eq!(rule.patterns.len(), 3);
    assert!(RuleSet::compile([rule]).is_ok());
}

#[test]
fn rejects_unknown_fields() {
    let yaml = format!("{MINIMAL}autofix: true\n");
    let err = parse("test", &yaml).unwrap_err();
    assert!(err.to_string().contains("autofix"), "{err}");
}

#[test]
fn rejects_fix_on_shor_rule() {
    let yaml = format!("{MINIMAL}fix: {{ description: d, replace: a, with: b }}\n");
    let rule = parse("test", &yaml).unwrap();
    assert!(matches!(
        RuleSet::compile([rule]),
        Err(RuleError::FixNotAllowed(id)) if id == "test.rule"
    ));
}

#[test]
fn error_names_the_origin() {
    let err = parse("rules/broken.yaml", "id: [").unwrap_err();
    assert!(err.to_string().starts_with("rules/broken.yaml:"), "{err}");
}

#[test]
fn every_builtin_rule_describes_its_cryptography() {
    for rule in builtin_rules().unwrap() {
        let crypto = rule
            .crypto
            .as_ref()
            .unwrap_or_else(|| panic!("{}: add a `crypto:` block to its profile", rule.id));
        if rule.category == shorwatch_core::Category::Shor {
            assert_eq!(
                crypto.nist_quantum_security_level, 0,
                "{}: Shor-broken algorithms have no quantum security",
                rule.id
            );
        }
    }
}

#[test]
fn builtin_libraries_compile() {
    assert!(!builtin_libraries().unwrap().is_empty());
}

/// `libraries/jsch.yaml` is the library `jsch`, and every group pattern is
/// anchored: an unanchored `bouncycastle` would claim every look-alike group.
#[test]
fn builtin_libraries_follow_their_conventions() {
    let catalog = Catalog::builtin().unwrap();
    assert!(!catalog.libraries.is_empty());
    for source in &catalog.libraries {
        let path = source.origin.strip_prefix("builtin:libraries/").unwrap();
        let id = path.trim_end_matches(".yaml");
        assert_eq!(
            source.doc.get("id").and_then(Value::as_str),
            Some(id),
            "{path}"
        );
    }
    for library in catalog.libraries().unwrap() {
        for coordinates in &library.matches {
            assert!(
                coordinates.group.starts_with('^') && coordinates.group.ends_with('$'),
                "{}: group `{}` must be anchored",
                library.id,
                coordinates.group
            );
            assert!(
                coordinates.artifact.starts_with('^'),
                "{}: artifact `{}` must be anchored",
                library.id,
                coordinates.artifact
            );
        }
    }
}

#[test]
fn libraries_are_not_rules() {
    let rule = "id: r\nplatform: jvm\npatterns: []\n";
    let catalog = catalog(&[("libraries/x.yaml", "id: x\n"), ("jvm/r.yaml", rule)]);
    assert_eq!(catalog.rules.len(), 1);
    assert_eq!(catalog.libraries.len(), 1);
}
