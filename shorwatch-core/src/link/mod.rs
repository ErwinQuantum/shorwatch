//! Cross-file resolution.
//!
//! Frontends lower each file in isolation. [`link`] connects what only makes
//! sense across files: the type hierarchy ([`hierarchy`]), receivers that
//! are calls to other files' methods ([`receivers`]), values passed to, or
//! returned by, methods of other files ([`flow`]), and values injected from
//! configuration (`@Value("${jwt.algorithm}")`) with the config entries that
//! define them ([`config`]). Compiled dependencies ([`Library`]) add the
//! types and return types the sources do not declare.

use crate::ir::{Arg, FactKind, Library, Platform, SourceUnit};

mod config;
mod flow;
mod hierarchy;
mod library;
mod receivers;

/// Resolves, in every unit, what depends on other units. Receivers are typed
/// first, so data flow sees calls through them; data flow comes before
/// config, since a value it brings from another file may be injected.
/// `library` may be empty: without it, only the sources' own types are known.
///
/// Code is linked one platform at a time: a Java method never receives the
/// arguments of a C# call that happens to share its name and arity. Config
/// reaches every platform.
pub fn link(units: &mut [SourceUnit], library: &Library) {
    for platform in [Platform::Jvm, Platform::Dotnet] {
        let of_platform: Vec<usize> = (0..units.len())
            .filter(|&i| units[i].language().platform() == platform)
            .collect();
        if of_platform.is_empty() {
            continue;
        }
        // Moved out and back (a placeholder in between), so the phases see a
        // contiguous slice of one platform's units.
        let mut group: Vec<SourceUnit> = of_platform
            .iter()
            .map(|&i| {
                let placeholder = SourceUnit::new("", units[i].language());
                std::mem::replace(&mut units[i], placeholder)
            })
            .collect();
        let relevant = library::relevant(library, &group);
        let hierarchy = hierarchy::Hierarchy::of(&group, &relevant.types);
        receivers::resolve(&mut group, &relevant.methods, &hierarchy);
        flow::resolve(&mut group, &hierarchy);
        for (&i, unit) in of_platform.iter().zip(group) {
            units[i] = unit;
        }
    }
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
