//! Turning declarative rules into their executable form, enforcing the
//! domain invariants on the way.

use std::collections::HashSet;

use regex::Regex;

use super::{ArgPattern, Category, HybridSpec, Marker, Pattern, Rule, RuleError};
use crate::ir::ScopeKind;

#[derive(Debug)]
pub(crate) struct CompiledArg {
    pub index: usize,
    pub regex: Regex,
}

#[derive(Debug)]
pub(crate) enum CompiledPattern {
    Call {
        receiver: String,
        method: String,
        arg: Option<CompiledArg>,
        origin: Option<CompiledArg>,
        unless_chain: Option<Regex>,
    },
    Construct {
        ty: String,
        arg: Option<CompiledArg>,
    },
    Field {
        owner: String,
        name: Option<Regex>,
    },
    Literal {
        value: Regex,
        unless_call: Option<Regex>,
    },
    Property {
        key: Regex,
        value: Option<Regex>,
        unless_property: Option<Regex>,
    },
    Key {
        algorithm: Option<Regex>,
        signature: Option<Regex>,
    },
}

#[derive(Debug)]
pub(crate) enum CompiledMarker {
    Import(Regex),
    Literal(Regex),
    Type(Regex),
}

#[derive(Debug)]
pub(crate) struct CompiledFix {
    pub description: String,
    pub replace: Regex,
    pub with: String,
}

#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub rule: Rule,
    pub patterns: Vec<CompiledPattern>,
    pub hybrid_scope: ScopeKind,
    pub markers: Vec<CompiledMarker>,
    pub fix: Option<CompiledFix>,
}

/// A validated, ready-to-evaluate collection of rules.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub(crate) rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub fn compile(rules: impl IntoIterator<Item = Rule>) -> Result<Self, RuleError> {
        let mut seen = HashSet::new();
        let mut compiled = Vec::new();
        for rule in rules {
            if !seen.insert(rule.id.clone()) {
                return Err(RuleError::DuplicateId(rule.id));
            }
            compiled.push(compile_rule(rule)?);
        }
        Ok(Self { rules: compiled })
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().map(|c| &c.rule)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn compile_rule(rule: Rule) -> Result<CompiledRule, RuleError> {
    let id = rule.id.as_str();
    let require = |value: bool, field| {
        if value {
            Ok(())
        } else {
            Err(RuleError::Empty {
                id: id.to_owned(),
                field,
            })
        }
    };
    require(!id.trim().is_empty(), "id")?;
    require(!rule.algorithm.trim().is_empty(), "algorithm")?;
    require(!rule.suggestion.trim().is_empty(), "suggestion")?;
    require(!rule.references.is_empty(), "references")?;
    require(!rule.patterns.is_empty(), "patterns")?;

    let regex = |pattern: &str| {
        Regex::new(pattern).map_err(|e| RuleError::InvalidRegex {
            id: id.to_owned(),
            pattern: pattern.to_owned(),
            reason: e.to_string(),
        })
    };
    let arg = |arg: &Option<ArgPattern>| -> Result<Option<CompiledArg>, RuleError> {
        arg.as_ref()
            .map(|a| {
                Ok(CompiledArg {
                    index: a.index,
                    regex: regex(&a.matches)?,
                })
            })
            .transpose()
    };

    let patterns = rule
        .patterns
        .iter()
        .map(|p| {
            Ok(match p {
                Pattern::Call {
                    receiver,
                    method,
                    arg: a,
                    origin,
                    unless_chain,
                } => CompiledPattern::Call {
                    receiver: receiver.clone(),
                    method: method.clone(),
                    arg: arg(a)?,
                    origin: arg(origin)?,
                    unless_chain: unless_chain.as_deref().map(regex).transpose()?,
                },
                Pattern::Construct { ty, arg: a } => CompiledPattern::Construct {
                    ty: ty.clone(),
                    arg: arg(a)?,
                },
                Pattern::Field { owner, matches } => CompiledPattern::Field {
                    owner: owner.clone(),
                    name: matches.as_deref().map(regex).transpose()?,
                },
                Pattern::Literal {
                    matches,
                    unless_call,
                } => CompiledPattern::Literal {
                    value: regex(matches)?,
                    unless_call: unless_call.as_deref().map(regex).transpose()?,
                },
                Pattern::Property {
                    key,
                    matches,
                    unless_property,
                } => CompiledPattern::Property {
                    key: regex(key)?,
                    value: matches.as_deref().map(regex).transpose()?,
                    unless_property: unless_property.as_deref().map(regex).transpose()?,
                },
                Pattern::Key {
                    algorithm,
                    signature,
                } => CompiledPattern::Key {
                    algorithm: algorithm.as_deref().map(regex).transpose()?,
                    signature: signature.as_deref().map(regex).transpose()?,
                },
            })
        })
        .collect::<Result<Vec<_>, RuleError>>()?;

    let (hybrid_scope, markers) = match &rule.hybrid {
        Some(spec) => {
            let markers = spec
                .markers
                .iter()
                .map(|m| {
                    Ok(match m {
                        Marker::Import(p) => CompiledMarker::Import(regex(p)?),
                        Marker::Literal(p) => CompiledMarker::Literal(regex(p)?),
                        Marker::Type(p) => CompiledMarker::Type(regex(p)?),
                    })
                })
                .collect::<Result<Vec<_>, RuleError>>()?;
            (spec.scope, markers)
        }
        None => (HybridSpec::default_scope(), Vec::new()),
    };

    // Reports turn references into links: a `javascript:` URL in someone
    // else's rules must not become one.
    if let Some(bad) = rule
        .references
        .iter()
        .find(|r| !(r.url.starts_with("https://") || r.url.starts_with("http://")))
    {
        return Err(RuleError::ReferenceNotHttp(
            rule.id.clone(),
            bad.url.clone(),
        ));
    }

    let fix = match &rule.fix {
        None => None,
        Some(_) if rule.category == Category::Shor => {
            return Err(RuleError::FixNotAllowed(rule.id.clone()));
        }
        Some(_) if !rule.patterns.iter().any(|p| p.arg().is_some()) => {
            return Err(RuleError::FixWithoutArg(rule.id.clone()));
        }
        Some(spec) => Some(CompiledFix {
            description: spec.description.clone(),
            replace: regex(&spec.replace)?,
            with: spec.with.clone(),
        }),
    };

    Ok(CompiledRule {
        rule,
        patterns,
        hybrid_scope,
        markers,
        fix,
    })
}
