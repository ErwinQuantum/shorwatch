//! Rule model.
//!
//! [`Rule`] is the fully resolved, declarative shape of a rule (assembled from
//! YAML files by `shorwatch-rules`, or built in code). [`RuleSet::compile`] turns
//! rules into their executable form and enforces the domain invariants, most
//! importantly that a rule for an algorithm broken by Shor can never carry an
//! automatic fix.

use std::collections::HashSet;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ir::{Platform, ScopeKind};

/// Which quantum attack weakens the algorithm. This decides what kind of
/// remediation is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Broken outright by Shor's algorithm (RSA, DH, ECC…). Migrating means
    /// changing the protocol, so remediation is advice only.
    Shor,
    /// Security margin halved by Grover's algorithm (AES-128, SHA-1, 3DES…).
    /// Usually fixed by a parameter change, so a mechanical fix is allowed.
    Grover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, e.g. `jvm.jca.rsa`. Used as the SARIF rule id.
    pub id: String,
    pub platform: Platform,
    /// Human name of the detected algorithm, e.g. `RSA`.
    pub algorithm: String,
    pub category: Category,
    pub severity: Severity,
    /// One-line summary of the problem.
    pub title: String,
    /// What was found and why it matters.
    pub message: String,
    /// Migration advice. Always educational text, never an edit.
    pub suggestion: String,
    pub references: Vec<Reference>,
    pub patterns: Vec<Pattern>,
    #[serde(default)]
    pub hybrid: Option<HybridSpec>,
    /// Mechanical fix. Only accepted for [`Category::Grover`] rules.
    #[serde(default)]
    pub fix: Option<FixSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Pattern {
    /// `Type.method(...)` or `receiver.method(...)` where the receiver has `type`.
    Call {
        #[serde(rename = "type")]
        receiver: String,
        method: String,
        #[serde(default)]
        arg: Option<ArgPattern>,
    },
    /// `new Type(...)`.
    Construct {
        #[serde(rename = "type")]
        ty: String,
        #[serde(default)]
        arg: Option<ArgPattern>,
    },
    /// `Type.FIELD`: a static field or enum constant of `type` whose name
    /// matches the `matches` regex (any field when absent).
    Field {
        #[serde(rename = "type")]
        owner: String,
        #[serde(default)]
        matches: Option<String>,
    },
    /// A configuration entry whose key matches the `key` regex and whose value
    /// matches `matches` (any value when absent).
    Property {
        key: String,
        #[serde(default)]
        matches: Option<String>,
    },
}

impl Pattern {
    fn arg(&self) -> Option<&ArgPattern> {
        match self {
            Pattern::Call { arg, .. } | Pattern::Construct { arg, .. } => arg.as_ref(),
            Pattern::Field { .. } | Pattern::Property { .. } => None,
        }
    }
}

/// Constrains one argument. `matches` is a regex tested against the
/// argument's literal value (integers are matched by their decimal text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgPattern {
    #[serde(default)]
    pub index: usize,
    pub matches: String,
}

/// How to recognise that a finding already lives next to post-quantum code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridSpec {
    /// How far around the finding to look for markers. Imports always count
    /// for the whole file.
    #[serde(default = "HybridSpec::default_scope")]
    pub scope: ScopeKind,
    pub markers: Vec<Marker>,
}

impl HybridSpec {
    fn default_scope() -> ScopeKind {
        ScopeKind::Type
    }
}

/// A regex matched against one kind of fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Marker {
    Import(String),
    Literal(String),
    Type(String),
}

/// Rewrite of the argument matched by the pattern: `replace` is a regex over
/// the argument's source text, `with` its replacement (`$1` etc. allowed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixSpec {
    pub description: String,
    pub replace: String,
    pub with: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("rule `{0}`: duplicate rule id")]
    DuplicateId(String),
    #[error("rule `{id}`: `{field}` must not be empty")]
    Empty { id: String, field: &'static str },
    #[error("rule `{id}`: invalid regex `{pattern}`: {reason}")]
    InvalidRegex {
        id: String,
        pattern: String,
        reason: String,
    },
    #[error(
        "rule `{0}`: Shor-category rules cannot declare a `fix`; migrating away from \
         RSA/ECC changes the protocol and must stay a human decision"
    )]
    FixNotAllowed(String),
    #[error("rule `{0}`: a `fix` needs at least one pattern with an `arg` to rewrite")]
    FixWithoutArg(String),
}

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
    },
    Construct {
        ty: String,
        arg: Option<CompiledArg>,
    },
    Field {
        owner: String,
        name: Option<Regex>,
    },
    Property {
        key: Regex,
        value: Option<Regex>,
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
                } => CompiledPattern::Call {
                    receiver: receiver.clone(),
                    method: method.clone(),
                    arg: arg(a)?,
                },
                Pattern::Construct { ty, arg: a } => CompiledPattern::Construct {
                    ty: ty.clone(),
                    arg: arg(a)?,
                },
                Pattern::Field { owner, matches } => CompiledPattern::Field {
                    owner: owner.clone(),
                    name: matches.as_deref().map(regex).transpose()?,
                },
                Pattern::Property { key, matches } => CompiledPattern::Property {
                    key: regex(key)?,
                    value: matches.as_deref().map(regex).transpose()?,
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
                },
                Pattern::Construct {
                    ty: "org.bouncycastle.crypto.engines.RSAEngine".into(),
                    arg: None,
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
}
