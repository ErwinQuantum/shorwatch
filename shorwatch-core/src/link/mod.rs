//! Cross-file resolution.
//!
//! Frontends lower each file in isolation. [`link`] connects what only makes
//! sense across files: the type hierarchy ([`hierarchy`]), receivers that
//! are calls to other files' methods ([`receivers`]), values passed to, or
//! returned by, methods of other files ([`flow`]), and values injected from
//! configuration (`@Value("${jwt.algorithm}")`) with the config entries that
//! define them ([`config`]). Compiled dependencies ([`Library`]) add the
//! types and return types the sources do not declare.

use crate::ir::{Arg, FactKind, Library, SourceUnit};

mod config;
mod flow;
mod hierarchy;
mod library;
mod receivers;

/// Resolves, in every unit, what depends on other units. Receivers are typed
/// first, so data flow sees calls through them; data flow comes before
/// config, since a value it brings from another file may be injected.
/// `library` may be empty: without it, only the sources' own types are known.
pub fn link(units: &mut [SourceUnit], library: &Library) {
    let relevant = library::relevant(library, units);
    let hierarchy = hierarchy::Hierarchy::of(units, &relevant.types);
    receivers::resolve(units, &relevant.methods, &hierarchy);
    flow::resolve(units, &hierarchy);
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
