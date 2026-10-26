//! Cross-file resolution.
//!
//! Frontends lower each file in isolation. [`link`] connects what only makes
//! sense across files: today, values injected from configuration
//! (`@Value("${jwt.algorithm}")`) and the config entries that define them.
//! It is still not data flow; a value only resolves where the injected field
//! or parameter itself is the argument.

use std::collections::HashMap;

use crate::ir::{ArgValue, CodeRole, FactKind, SourceUnit};

type Properties = HashMap<String, Vec<String>>;

/// Fills [`ArgValue::Injected::resolved`] in every unit from the
/// [`FactKind::Property`] facts of the config units. Production code only
/// sees production config; test code sees both, as on a test classpath
/// (`src/main/resources` and `src/test/resources`). Deterministic: values keep
/// the order of `units`, then of the file, without duplicates.
pub fn link(units: &mut [SourceUnit]) {
    let production = properties(units, |role| role == CodeRole::Production);
    let all = properties(units, |_| true);
    if all.is_empty() {
        return;
    }

    for unit in units.iter_mut() {
        let properties = match unit.role() {
            CodeRole::Production => &production,
            CodeRole::Test => &all,
        };
        for fact in &mut unit.facts {
            let args: Vec<_> = match &mut fact.kind {
                FactKind::Call {
                    args,
                    receiver_origin,
                    ..
                } => args
                    .iter_mut()
                    .chain(receiver_origin.iter_mut().flatten())
                    .collect(),
                FactKind::Construct { args, .. } => args.iter_mut().collect(),
                _ => continue,
            };
            for arg in args {
                resolve(&mut arg.value, properties);
            }
        }
    }
}

/// Injected values, also among data-flow candidates (a `@Value` parameter
/// passed on to another method).
fn resolve(value: &mut ArgValue, properties: &Properties) {
    match value {
        ArgValue::Injected { key, resolved, .. } => *resolved = lookup(properties, key),
        ArgValue::OneOf(candidates) => {
            for candidate in candidates {
                resolve(&mut candidate.value, properties);
            }
        }
        _ => {}
    }
}

/// Every config value of the units whose role passes `include`, by key.
fn properties(units: &[SourceUnit], include: impl Fn(CodeRole) -> bool) -> Properties {
    let mut properties = Properties::new();
    for unit in units.iter().filter(|u| include(u.role())) {
        for fact in unit.facts() {
            if let FactKind::Property { key, value } = &fact.kind {
                let values = properties.entry(canonical(key)).or_default();
                if !values.contains(value) {
                    values.push(value.clone());
                }
            }
        }
    }
    properties
}

/// Values for `key`, or for its list elements (`key[0]`, `key[1]`...) when the
/// key names a list.
fn lookup(properties: &Properties, key: &str) -> Vec<String> {
    let key = canonical(key);
    if let Some(values) = properties.get(&key) {
        return values.clone();
    }
    let prefix = format!("{key}[");
    let mut elements: Vec<_> = properties
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .collect();
    elements.sort_by(|a, b| a.0.cmp(b.0));
    elements.into_iter().flat_map(|(_, v)| v.clone()).collect()
}

/// Spring-style relaxed binding: `jwt.jws-algorithms`, `jwt.jwsAlgorithms`
/// and `jwt.jws_algorithms` name the same property.
fn canonical(key: &str) -> String {
    key.chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Arg, Language, Location};

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
}
