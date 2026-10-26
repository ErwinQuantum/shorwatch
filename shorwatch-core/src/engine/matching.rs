//! Whether a compiled pattern matches one fact.

use crate::ir::{Arg, Fact, FactKind};
use crate::rule::{CompiledArg, CompiledPattern};

pub(super) struct Match<'a> {
    /// The argument the pattern constrained, if it constrained one.
    pub(super) arg: Option<&'a Arg>,
}

pub(super) fn match_pattern<'a>(pattern: &CompiledPattern, fact: &'a Fact) -> Option<Match<'a>> {
    // An absent regex accepts anything.
    let optional =
        |re: &Option<regex::Regex>, text: &str| re.as_ref().is_none_or(|re| re.is_match(text));
    let (args, arg_pattern) = match (pattern, &fact.kind) {
        (
            CompiledPattern::Call {
                receiver,
                method,
                arg,
                origin,
            },
            FactKind::Call {
                receiver: Some(actual),
                method: actual_method,
                args,
                receiver_origin,
            },
        ) if actual_method == method
            && actual.is(receiver)
            && origin_allows(origin.as_ref(), receiver_origin.as_deref()) =>
        {
            (args, arg)
        }
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
        (
            CompiledPattern::Literal { value, unless_call },
            FactKind::Literal {
                value: literal,
                calls,
            },
        ) => {
            let excluded = unless_call
                .as_ref()
                .is_some_and(|re| calls.iter().any(|call| re.is_match(call)));
            return (value.is_match(literal) && !excluded).then_some(Match { arg: None });
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
    arg_matches(arg_pattern, arg).then_some(Match { arg: Some(arg) })
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
