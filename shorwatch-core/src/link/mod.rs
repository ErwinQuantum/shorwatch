//! Cross-file resolution.
//!
//! Frontends lower each file in isolation. [`link`] connects what only makes
//! sense across files: values passed to, or returned by, methods of other
//! files ([`flow`]), and values injected from configuration
//! (`@Value("${jwt.algorithm}")`) with the config entries that define them
//! ([`config`]).

use crate::ir::{Arg, FactKind, SourceUnit};

mod config;
mod flow;

/// Resolves, in every unit, what depends on other units. Data flow comes
/// first: a value it brings from another file may itself be injected.
pub fn link(units: &mut [SourceUnit]) {
    flow::resolve(units);
    config::inject(units);
}

/// The arguments of a fact: those of a call or constructor, then the
/// factory arguments a call's receiver was created with.
fn args(kind: &FactKind) -> Vec<&Arg> {
    match kind {
        FactKind::Call {
            args,
            receiver_origin,
            ..
        } => args
            .iter()
            .chain(receiver_origin.iter().flatten())
            .collect(),
        FactKind::Construct { args, .. } => args.iter().collect(),
        _ => Vec::new(),
    }
}

/// [`args`], mutable and in the same order.
fn args_mut(kind: &mut FactKind) -> Vec<&mut Arg> {
    match kind {
        FactKind::Call {
            args,
            receiver_origin,
            ..
        } => args
            .iter_mut()
            .chain(receiver_origin.iter_mut().flatten())
            .collect(),
        FactKind::Construct { args, .. } => args.iter_mut().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
