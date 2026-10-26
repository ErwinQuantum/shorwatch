//! Values injected from configuration (`@Value("${jwt.algorithm}")`),
//! resolved against the config entries that define them.

use std::collections::HashMap;

use crate::ir::{ArgValue, CodeRole, FactKind, SourceUnit};

type Properties = HashMap<String, Vec<String>>;

/// Fills [`ArgValue::Injected::resolved`] in every unit from the
/// [`FactKind::Property`] facts of the config units. Production code only
/// sees production config; test code sees both, as on a test classpath
/// (`src/main/resources` and `src/test/resources`). Deterministic: values keep
/// the order of `units`, then of the file, without duplicates.
pub(super) fn inject(units: &mut [SourceUnit]) {
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
            for arg in super::args_mut(&mut fact.kind) {
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
