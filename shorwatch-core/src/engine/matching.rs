//! Whether a compiled pattern matches one fact.

use crate::ir::{Arg, ArgValue, Fact, FactKind, FlowStep, SourceUnit};
use crate::rule::{CompiledArg, CompiledPattern};

pub(super) struct Match<'a> {
    /// The argument the pattern constrained, if it constrained one.
    pub(super) arg: Option<&'a Arg>,
    /// The path of the matched value, when data flow resolved it.
    pub(super) flow: Vec<FlowStep>,
}

impl Match<'_> {
    const NONE: Self = Self {
        arg: None,
        flow: Vec::new(),
    };
}

pub(super) fn match_pattern<'a>(
    pattern: &CompiledPattern,
    fact: &'a Fact,
    unit: &SourceUnit,
) -> Option<Match<'a>> {
    // An absent regex accepts anything.
    let optional =
        |re: &Option<regex::Regex>, text: &str| re.as_ref().is_none_or(|re| re.is_match(text));
    let (args, arg_pattern) = match (pattern, &fact.kind) {
        (
            CompiledPattern::Call {
                receiver,
                method,
                arg,
                with_arg,
                origin,
                unless_chain,
            },
            FactKind::Call {
                receiver: Some(actual),
                method: actual_method,
                args,
                receiver_origin,
                chain,
                ..
            },
        ) if actual_method == method
            && actual.is(receiver)
            && with_arg
                .as_ref()
                .is_none_or(|p| args.get(p.index).is_some_and(|a| arg_matches(p, a)))
            && origin_allows(origin.as_ref(), receiver_origin.as_deref())
            && !unless_chain
                .as_ref()
                .is_some_and(|re| chain.iter().any(|next| re.is_match(next))) =>
        {
            (args, arg)
        }
        (CompiledPattern::Construct { ty, arg }, FactKind::Construct { ty: actual, args })
            if actual.is(ty) =>
        {
            (args, arg)
        }
        (
            CompiledPattern::Field {
                owner,
                name,
                unless_call,
            },
            FactKind::Field {
                owner: actual,
                name: field,
                calls,
            },
        ) => {
            let excluded = unless_call
                .as_ref()
                .is_some_and(|re| calls.iter().any(|call| re.is_match(call)));
            return (actual.is(owner) && optional(name, field) && !excluded).then_some(Match::NONE);
        }
        (
            CompiledPattern::Literal {
                value,
                unless_call,
                in_call,
            },
            FactKind::Literal {
                value: literal,
                calls,
            },
        ) => {
            let excluded = unless_call
                .as_ref()
                .is_some_and(|re| calls.iter().any(|call| re.is_match(call)));
            let inside = in_call
                .as_ref()
                .is_none_or(|re| calls.iter().any(|call| re.is_match(call)));
            return (value.is_match(literal) && !excluded && inside).then_some(Match::NONE);
        }
        (
            CompiledPattern::Property {
                key,
                value,
                unless_property,
            },
            FactKind::Property { key: k, value: v },
        ) => {
            let overridden = unless_property.as_ref().is_some_and(|re| {
                unit.facts()
                    .iter()
                    .any(|f| matches!(&f.kind, FactKind::Property { key, .. } if re.is_match(key)))
            });
            return (key.is_match(k) && optional(value, v) && !overridden).then_some(Match::NONE);
        }
        (
            CompiledPattern::Key {
                algorithm,
                signature,
            },
            FactKind::Key {
                algorithm: actual,
                signature: signed,
                ..
            },
        ) => {
            // A signature pattern needs a signature: keys alone have none.
            let signed = match (signature, signed) {
                (None, _) => true,
                (Some(re), Some(signed)) => re.is_match(signed),
                (Some(_), None) => false,
            };
            return (optional(algorithm, actual) && signed).then_some(Match::NONE);
        }
        _ => return None,
    };

    let Some(arg_pattern) = arg_pattern else {
        return Some(Match::NONE);
    };
    let arg = args.get(arg_pattern.index)?;
    arg_matches(arg_pattern, arg).then(|| Match {
        arg: Some(arg),
        flow: matched_flow(arg_pattern, arg),
    })
}

/// The path of the first data-flow candidate that matches.
fn matched_flow(pattern: &CompiledArg, arg: &Arg) -> Vec<FlowStep> {
    let ArgValue::OneOf(candidates) = &arg.value else {
        return Vec::new();
    };
    candidates
        .iter()
        .find(|c| c.value.texts().iter().any(|t| pattern.regex.is_match(t)))
        .map(|c| c.flow.clone())
        .unwrap_or_default()
}

fn arg_matches(pattern: &CompiledArg, arg: &Arg) -> bool {
    arg.match_texts()
        .iter()
        .any(|text| pattern.regex.is_match(text))
}

/// Whether the receiver's origin is compatible with the pattern. Only an
/// origin known *not* to match rules the call out; an unknown one (no
/// factory seen, or a factory argument without a static value) keeps it.
fn origin_allows(pattern: Option<&CompiledArg>, origin: Option<&[Arg]>) -> bool {
    let (Some(pattern), Some(origin)) = (pattern, origin) else {
        return true;
    };
    match origin.get(pattern.index) {
        Some(arg) if !arg.match_texts().is_empty() => arg_matches(pattern, arg),
        _ => true,
    }
}
