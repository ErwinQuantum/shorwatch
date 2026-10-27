//! The part of a [`Library`] a project can use. A classpath holds tens of
//! thousands of types; the project calls a handful of their methods. Kept:
//! the types call chains start from and the types the project's methods
//! return or its types extend, their supertypes, the methods of those types
//! that the chains call, and, in turn, the types those methods return.

use std::collections::{HashMap, HashSet};

use crate::ir::{
    CallOwner, CallRef, FactKind, Library, MethodSummary, SourceUnit, TypeDecl, TypeRef,
};

#[derive(Debug, Default)]
pub(super) struct Relevant<'l> {
    pub(super) types: Vec<&'l TypeDecl>,
    pub(super) methods: Vec<&'l MethodSummary>,
}

pub(super) fn relevant<'l>(library: &'l Library, units: &[SourceUnit]) -> Relevant<'l> {
    if library.is_empty() {
        return Relevant::default();
    }
    let mut called = HashSet::new();
    let mut seeds: Vec<&TypeRef> = Vec::new();
    for fact in units.iter().flat_map(SourceUnit::facts) {
        if let FactKind::Call {
            receiver_call: Some(call),
            ..
        } = &fact.kind
        {
            chain(call, &mut called, &mut seeds);
        }
    }
    seeds.extend(
        units
            .iter()
            .flat_map(SourceUnit::methods)
            .filter_map(|m| m.return_type.as_ref()),
    );
    seeds.extend(
        units
            .iter()
            .flat_map(SourceUnit::types)
            .flat_map(|decl| &decl.supertypes),
    );

    let mut by_simple: HashMap<&str, Vec<&TypeDecl>> = HashMap::new();
    for decl in &library.types {
        by_simple.entry(simple(&decl.name)).or_default().push(decl);
    }
    let mut methods_of: HashMap<&str, Vec<&MethodSummary>> = HashMap::new();
    for method in &library.methods {
        if called.contains(&(method.name.as_str(), method.arity)) {
            methods_of.entry(&method.owner).or_default().push(method);
        }
    }
    let resolve = |reference: &TypeRef| -> Vec<&'l TypeDecl> {
        by_simple
            .get(simple(&reference.name))
            .into_iter()
            .flatten()
            .filter(|decl| reference.is(&decl.name))
            .copied()
            .collect()
    };

    let mut stack: Vec<&TypeDecl> = seeds.into_iter().flat_map(resolve).collect();
    let mut seen = HashSet::new();
    let mut relevant = Relevant::default();
    while let Some(decl) = stack.pop() {
        if !seen.insert(decl.name.as_str()) {
            continue;
        }
        relevant.types.push(decl);
        stack.extend(decl.supertypes.iter().flat_map(resolve));
        for method in methods_of.get(decl.name.as_str()).into_iter().flatten() {
            relevant.methods.push(method);
            stack.extend(method.return_type.iter().flat_map(resolve));
        }
    }
    relevant
}

/// The methods a call chain names, and the type it starts from.
fn chain<'u>(
    call: &'u CallRef,
    called: &mut HashSet<(&'u str, usize)>,
    seeds: &mut Vec<&'u TypeRef>,
) {
    called.insert((call.method.as_str(), call.arity));
    match &call.owner {
        CallOwner::Type(ty) => seeds.push(ty),
        CallOwner::Call(inner) => chain(inner, called, seeds),
    }
}

fn simple(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}
