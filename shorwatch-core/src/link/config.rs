//! Values injected from configuration (`@Value("${jwt.algorithm}")`, or the
//! property of an options type bound to a section), resolved against the
//! config entries that define them.

use std::collections::HashMap;

use crate::ir::{ArgValue, Candidate, CodeRole, FactKind, FlowStep, SourceUnit, TypeRef};

type Properties = HashMap<String, Vec<String>>;

/// The sections the project binds types to: `Configure<JwtOptions>(config
/// .GetSection("Jwt"))` is `JwtOptions` and `Jwt`.
struct Bindings(Vec<(TypeRef, Vec<String>)>);

impl Bindings {
    fn of(units: &[SourceUnit]) -> Self {
        let mut bindings: Vec<(TypeRef, Vec<String>)> = Vec::new();
        for unit in units {
            for fact in unit.facts() {
                if let FactKind::Bind { ty, section } = &fact.kind {
                    let sections = section.match_texts();
                    if !sections.is_empty() {
                        bindings.push((ty.clone(), sections));
                    }
                }
            }
        }
        Self(bindings)
    }

    /// The configuration keys that fill `owner.property`, one per section the
    /// type is bound to.
    fn keys(&self, owner: &str, property: &str) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for (ty, sections) in &self.0 {
            if ty.is(owner) {
                for section in sections {
                    let key = format!("{section}.{property}");
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
        }
        keys
    }
}

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
    let bindings = Bindings::of(units);

    for unit in units.iter_mut() {
        let properties = match unit.role() {
            CodeRole::Production => &production,
            CodeRole::Test => &all,
        };
        for fact in &mut unit.facts {
            for arg in super::args_mut(&mut fact.kind) {
                resolve(&mut arg.value, properties, &bindings);
            }
        }
    }
}

/// Injected values, also among data-flow candidates (a `@Value` parameter
/// passed on to another method).
fn resolve(value: &mut ArgValue, properties: &Properties, bindings: &Bindings) {
    match value {
        ArgValue::Injected { key, resolved, .. } => *resolved = lookup(properties, key),
        ArgValue::OneOf(candidates) => {
            for candidate in candidates {
                resolve(&mut candidate.value, properties, bindings);
                explain_binding(candidate, bindings);
            }
        }
        ArgValue::Bound {
            owner,
            property,
            resolved,
            ..
        } => {
            resolved.clear();
            for key in bindings.keys(owner, property) {
                for value in lookup(properties, &key) {
                    if !resolved.contains(&value) {
                        resolved.push(value);
                    }
                }
            }
        }
        _ => {}
    }
}

/// A bound property takes its value from the configuration, not from its
/// initializer: the path says where the property is and which key fills it.
fn explain_binding(candidate: &mut Candidate, bindings: &Bindings) {
    let ArgValue::Bound {
        owner,
        property,
        resolved,
        ..
    } = &candidate.value
    else {
        return;
    };
    let keys = bindings.keys(owner, property);
    let Some(first) = candidate.flow.first() else {
        return;
    };
    if resolved.is_empty() || keys.is_empty() {
        return;
    }
    let step = |note: String| FlowStep {
        path: first.path.clone(),
        location: first.location,
        note,
    };
    candidate.flow = vec![
        step(format!("{property} is a settable property of {owner}")),
        step(format!(
            "{property} is bound to the configuration key {}",
            keys.join(", ")
        )),
    ];
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
/// and `jwt.jws_algorithms` name the same property. .NET separates the
/// levels of a key with `:` (`Jwt:Algorithm`), which names `Jwt.Algorithm`.
fn canonical(key: &str) -> String {
    key.chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .map(|c| if c == ':' { '.' } else { c })
        .flat_map(char::to_lowercase)
        .collect()
}
