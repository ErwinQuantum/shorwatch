//! Receivers that are themselves calls (`Crypto.provider().keyPairGen("RSA")`)
//! get the declared return type of the method called, found in whichever
//! file declares it. Rules and data flow then see `provider()`'s type.

use std::collections::HashMap;

use super::hierarchy::Hierarchy;
use crate::ir::{FactKind, SourceUnit, TypeRef};

pub(super) fn resolve(units: &mut [SourceUnit], hierarchy: &Hierarchy) {
    let typed = {
        let mut returns: HashMap<(&str, usize), Vec<(&str, &TypeRef)>> = HashMap::new();
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
                let FactKind::Call {
                    receiver: None,
                    receiver_call: Some(call),
                    ..
                } = &fact.kind
                else {
                    continue;
                };
                let mut types = returns
                    .get(&(call.method.as_str(), call.arity))
                    .into_iter()
                    .flatten()
                    .filter(|(owner, _)| hierarchy.reaches(&call.owner, owner))
                    .map(|(_, ty)| *ty);
                // Implementations may declare the same type: it must agree.
                if let Some(first) = types.next()
                    && types.all(|ty| ty.name == first.name)
                {
                    typed.push((u, f, first.clone()));
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
