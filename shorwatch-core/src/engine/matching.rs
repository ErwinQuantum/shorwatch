//! Whether a compiled pattern matches one fact.

use crate::ir::{Arg, Fact, FactKind};
use crate::rule::CompiledPattern;

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
