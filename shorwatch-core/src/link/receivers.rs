//! Receivers that are themselves calls (`Crypto.provider().keyPairGen("RSA")`)
//! get the declared return type of the method called, found in whichever
//! file declares it. Chains (`a.b().c().d()`) are typed one call at a time,
//! from the innermost out. Rules and data flow then see `provider()`'s type.

use std::collections::HashMap;

use super::hierarchy::Hierarchy;
use crate::ir::{CallOwner, CallRef, FactKind, SourceUnit, TypeRef};

/// Declared return types by method name and arity, with their owners.
type Returns<'a> = HashMap<(&'a str, usize), Vec<(&'a str, &'a TypeRef)>>;

pub(super) fn resolve(units: &mut [SourceUnit], hierarchy: &Hierarchy) {
    let typed = {
        let mut returns: Returns = HashMap::new();
        for summary in units.iter().flat_map(SourceUnit::methods) {
            if let Some(ty) = &summary.return_type {
                returns
                    .entry((summary.name.as_str(), summary.arity))
                    .or_default()
                    .push((summary.owner.as_str(), ty));
            }
        }
        let mut typed = Vec::new();
        for (u, unit) in units.iter().enumerate() {
            for (f, fact) in unit.facts().iter().enumerate() {
                if let FactKind::Call {
                    receiver: None,
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

/// The type `call` returns, when every method it may reach declares the same.
fn return_type<'a>(
    call: &CallRef,
    returns: &Returns<'a>,
    hierarchy: &Hierarchy,
) -> Option<&'a TypeRef> {
    let owner = match &call.owner {
        CallOwner::Type(ty) => ty,
        CallOwner::Call(inner) => return_type(inner, returns, hierarchy)?,
    };
    let mut types = returns
        .get(&(call.method.as_str(), call.arity))
        .into_iter()
        .flatten()
        .filter(|(declaring, _)| hierarchy.reaches(owner, declaring))
        .map(|(_, ty)| *ty);
    // Implementations may declare the same type: it must agree.
    let first = types.next()?;
    types.all(|ty| ty.name == first.name).then_some(first)
}
