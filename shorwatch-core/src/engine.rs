use crate::finding::{Finding, HybridEvidence, Status, SuggestedFix};
use crate::ir::{Arg, Fact, FactKind, SourceUnit};
use crate::rule::{CompiledMarker, CompiledPattern, CompiledRule, RuleSet};

/// Evaluates every rule for the unit's platform against the unit.
///
/// Pure and deterministic: findings are ordered by position, then rule id.
pub fn analyze(unit: &SourceUnit, rules: &RuleSet) -> Vec<Finding> {
    let platform = unit.language().platform();
    let mut findings = Vec::new();
    for rule in rules.rules.iter().filter(|r| r.rule.platform == platform) {
        for fact in unit.facts() {
            if let Some(matched) = rule.patterns.iter().find_map(|p| match_pattern(p, fact)) {
                findings.push(build_finding(unit, rule, fact, matched));
            }
        }
    }
    findings.sort_by(|a, b| (a.location.start, &a.rule_id).cmp(&(b.location.start, &b.rule_id)));
    findings
}

struct Match<'a> {
    /// The argument the pattern constrained, if it constrained one.
    arg: Option<&'a Arg>,
}

fn match_pattern<'a>(pattern: &CompiledPattern, fact: &'a Fact) -> Option<Match<'a>> {
    // An absent regex accepts anything.
    let optional =
        |re: &Option<regex::Regex>, text: &str| re.as_ref().is_none_or(|re| re.is_match(text));
    let (args, arg_pattern) = match (pattern, &fact.kind) {
        (
            CompiledPattern::Call {
                receiver,
                method,
                arg,
            },
            FactKind::Call {
                receiver: Some(actual),
                method: actual_method,
                args,
            },
        ) if actual_method == method && actual.is(receiver) => (args, arg),
        (CompiledPattern::Construct { ty, arg }, FactKind::Construct { ty: actual, args })
            if actual.is(ty) =>
        {
            (args, arg)
        }
        (
            CompiledPattern::Field { owner, name },
            FactKind::Field {
                owner: actual,
                name: field,
            },
        ) => {
            return (actual.is(owner) && optional(name, field)).then_some(Match { arg: None });
        }
        (CompiledPattern::Property { key, value }, FactKind::Property { key: k, value: v }) => {
            return (key.is_match(k) && optional(value, v)).then_some(Match { arg: None });
        }
        _ => return None,
    };

    let Some(arg_pattern) = arg_pattern else {
        return Some(Match { arg: None });
    };
    let arg = args.get(arg_pattern.index)?;
    arg.match_texts()
        .iter()
        .any(|text| arg_pattern.regex.is_match(text))
        .then_some(Match { arg: Some(arg) })
}

fn build_finding(unit: &SourceUnit, rule: &CompiledRule, fact: &Fact, matched: Match) -> Finding {
    let hybrid_evidence = hybrid_evidence(unit, rule, fact);
    let spec = &rule.rule;
    Finding {
        rule_id: spec.id.clone(),
        algorithm: spec.algorithm.clone(),
        category: spec.category,
        severity: spec.severity,
        status: if hybrid_evidence.is_some() {
            Status::InTransition
        } else {
            Status::Vulnerable
        },
        title: spec.title.clone(),
        message: spec.message.clone(),
        suggestion: spec.suggestion.clone(),
        references: spec.references.clone(),
        path: unit.path().to_owned(),
        location: fact.location,
        hybrid_evidence,
        fix: suggested_fix(rule, &matched),
    }
}

fn hybrid_evidence(unit: &SourceUnit, rule: &CompiledRule, fact: &Fact) -> Option<HybridEvidence> {
    if rule.markers.is_empty() {
        return None;
    }
    let region = unit.enclosing(fact.scope, rule.hybrid_scope);
    unit.facts().iter().find_map(|other| {
        let in_region = unit.is_within(other.scope, region);
        let text = rule
            .markers
            .iter()
            .find_map(|marker| match (marker, &other.kind) {
                // Imports are file-wide, so they count regardless of the region.
                (CompiledMarker::Import(re), FactKind::Import { path }) => {
                    re.is_match(path).then_some(path.as_str())
                }
                (CompiledMarker::Literal(re), FactKind::Literal { value })
                | (CompiledMarker::Literal(re), FactKind::Property { value, .. })
                    if in_region =>
                {
                    re.is_match(value).then_some(value.as_str())
                }
                (CompiledMarker::Type(re), FactKind::Construct { ty, .. })
                | (CompiledMarker::Type(re), FactKind::Field { owner: ty, .. })
                    if in_region =>
                {
                    re.is_match(ty.best_name()).then_some(ty.best_name())
                }
                (
                    CompiledMarker::Type(re),
                    FactKind::Call {
                        receiver: Some(ty), ..
                    },
                ) if in_region => re.is_match(ty.best_name()).then_some(ty.best_name()),
                _ => None,
            })?;
        Some(HybridEvidence {
            text: text.to_owned(),
            location: other.location,
        })
    })
}

fn suggested_fix(rule: &CompiledRule, matched: &Match) -> Option<SuggestedFix> {
    let fix = rule.fix.as_ref()?;
    let arg = matched.arg?;
    if arg.resolved_via.is_some() || !fix.replace.is_match(&arg.raw) {
        return None;
    }
    Some(SuggestedFix {
        description: fix.description.clone(),
        location: arg.location,
        replacement: fix
            .replace
            .replace_all(&arg.raw, fix.with.as_str())
            .into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Language, Location, ScopeKind, TypeRef};
    use crate::rule::tests::rsa_rule;
    use crate::rule::{ArgPattern, Category, FixSpec, Pattern, Rule};

    fn loc(line: u32) -> Location {
        Location::line(line, 1, 40)
    }

    fn get_instance(
        unit: &mut SourceUnit,
        scope: crate::ir::ScopeId,
        ty: &str,
        alg: &str,
        line: u32,
    ) {
        unit.push(
            FactKind::Call {
                receiver: Some(TypeRef::qualified(ty)),
                method: "getInstance".into(),
                args: vec![Arg::str(alg, loc(line))],
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
        let (mut unit, _, method) = unit_with_method();
        unit.push(
            FactKind::Call {
                receiver: Some(TypeRef::simple("KeyGenerator")),
                method: "init".into(),
                args: vec![arg],
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
        });
        rule.hybrid.as_mut().unwrap().markers =
            vec![crate::rule::Marker::Type("(?i)ml-?dsa".into())];
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
}
