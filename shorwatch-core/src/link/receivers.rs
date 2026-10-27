//! Receivers that are themselves calls (`Crypto.provider().keyPairGen("RSA")`)
//! get the declared return type of the method called, found in whichever
//! file (or library) declares it, as do variables initialized by such a call.
//! Chains (`a.b().c().d()`) are typed one call at a time, from the innermost
//! out. Rules and data flow then see `provider()`'s type.

use std::collections::HashMap;

use super::hierarchy::Hierarchy;
use crate::ir::{CallOwner, CallRef, FactKind, MethodSummary, SourceUnit, TypeRef};

/// Declared return types by declaring type, method name and arity.
type Returns<'k, 'v> = HashMap<(&'k str, &'k str, usize), Vec<&'v TypeRef>>;

pub(super) fn resolve(units: &mut [SourceUnit], library: &[&MethodSummary], hierarchy: &Hierarchy) {
    let typed = {
        let mut returns: Returns = HashMap::new();
        let summaries = units.iter().flat_map(SourceUnit::methods);
        for summary in summaries.chain(library.iter().copied()) {
            if let Some(ty) = &summary.return_type {
                returns
                    .entry((&summary.owner, &summary.name, summary.arity))
                    .or_default()
                    .push(ty);
            }
        }
        let mut typed = Vec::new();
        for (u, unit) in units.iter().enumerate() {
            for (f, fact) in unit.facts().iter().enumerate() {
                // A declared return type also wins over the frontend's guess
                // (`val p = Keys.provider()` is not a `Keys`).
                if let FactKind::Call {
                    receiver_call: Some(call),
                    ..
                } = &fact.kind
                    && let Some(ty) = return_type(call, &returns, hierarchy)
                {
                    typed.push((u, f, ty.clone()));
                }
            }
        }
        typed
    };
    for (u, f, ty) in typed {
        if let FactKind::Call { receiver, .. } = &mut units[u].facts[f].kind {
            *receiver = Some(ty);
        }
    }
}

/// The type `call` returns: the one its receiver's type declares, or else
/// the one its supertypes declare (the method is inherited), when they agree.
fn return_type<'v>(
    call: &CallRef,
    returns: &Returns<'_, 'v>,
    hierarchy: &Hierarchy,
) -> Option<&'v TypeRef> {
    let owner = match &call.owner {
        CallOwner::Type(ty) => ty,
        CallOwner::Call(inner) => return_type(inner, returns, hierarchy)?,
    };
    let mut types: Vec<&TypeRef> = Vec::new();
    for ty in hierarchy.declared(owner) {
        let own = declared_by(returns, ty, call);
        if own.is_empty() {
            for ancestor in hierarchy.with_ancestors(ty).skip(1) {
                types.extend(declared_by(returns, ancestor, call));
            }
        } else {
            types.extend(own);
        }
    }
    // Overloads, or supertypes that differ: it must agree.
    let first = *types.first()?;
    types
        .iter()
        .all(|ty| ty.name == first.name)
        .then_some(first)
}

fn declared_by<'v>(returns: &Returns<'_, 'v>, ty: &str, call: &CallRef) -> Vec<&'v TypeRef> {
    returns
        .get(&(ty, call.method.as_str(), call.arity))
        .cloned()
        .unwrap_or_default()
}
