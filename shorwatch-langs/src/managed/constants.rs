//! Enum constants one at a time. `LEGACY("RSA")` is a construction of the
//! enum, so `kind.getJceName()` on a variable reaches every constant's value
//! (see [`super::flow`]). A *specific* constant, `KeyKind.LEGACY.getJceName()`,
//! is one of them: here the enum's accessors are evaluated once per
//! constant, with the constructor bound to that constant's arguments, and
//! published as the methods of a type of its own, `KeyKind.LEGACY`, which is
//! what a call on that receiver is typed as.

use shorwatch_core::ir::{Location, MethodSummary, ScopeId, ScopeKind, TypeDecl};

use super::flow::{Context, Entered};
use super::{ManagedFile, Pending, PendingArg};

/// An enum constant with arguments: `LEGACY("RSA")`.
#[derive(Debug)]
pub(crate) struct ConstantArgs {
    enum_scope: ScopeId,
    name: String,
    args: Vec<PendingArg>,
}

impl ManagedFile {
    /// Pairs each constant of an enum with the construction its frontend
    /// deferred at the constant's location. Before the pending facts are
    /// resolved (and so consumed).
    pub(super) fn gather_constant_args(&mut self) {
        if self.enum_constants.is_empty() {
            return;
        }
        let mut built: Vec<(ScopeId, &Location, &Vec<PendingArg>)> = Vec::new();
        for (pending, scope, location) in &self.pending {
            if let Pending::Construct { args, .. } = pending
                && self.enum_constants.contains_key(scope)
            {
                built.push((*scope, location, args));
            }
        }
        let mut found = Vec::new();
        for (enum_scope, constants) in &self.enum_constants {
            for (name, location) in constants {
                if let Some((_, _, args)) = built
                    .iter()
                    .find(|(scope, at, _)| scope == enum_scope && *at == location)
                {
                    found.push(ConstantArgs {
                        enum_scope: *enum_scope,
                        name: name.clone(),
                        args: (*args).clone(),
                    });
                }
            }
        }
        found.sort_by(|a, b| (a.enum_scope.0, &a.name).cmp(&(b.enum_scope.0, &b.name)));
        self.constant_args = found;
    }

    /// The type each such constant is: `com.acme.KeyKind.LEGACY`.
    pub(super) fn constant_types(&self) -> Vec<TypeDecl> {
        self.constant_args
            .iter()
            .filter_map(|c| {
                Some(TypeDecl {
                    name: format!("{}.{}", self.owner(c.enum_scope)?, c.name),
                    supertypes: Vec::new(),
                })
            })
            .collect()
    }

    /// What the accessors of the enum return for each constant: the methods
    /// without parameters, and a Kotlin primary-constructor property.
    pub(super) fn constant_summaries(&self) -> Vec<MethodSummary> {
        let mut summaries = Vec::new();
        for constant in &self.constant_args {
            let (Some(owner), Some(constructor)) = (
                self.owner(constant.enum_scope),
                self.constructor_of(constant.enum_scope, constant.args.len()),
            ) else {
                continue;
            };
            let owner = format!("{owner}.{}", constant.name);
            let context = || Context {
                trail: Vec::new(),
                calls: vec![Entered {
                    method: constructor,
                    args: &constant.args,
                    scope: constant.enum_scope,
                }],
            };
            let mut returned = Vec::new();
            for (index, scope) in self.unit.scopes().iter().enumerate() {
                let Ok(id) = u32::try_from(index).map(ScopeId) else {
                    continue;
                };
                let Some(name) = scope.name.as_deref() else {
                    continue;
                };
                if scope.kind != ScopeKind::Method
                    || scope.parent != Some(constant.enum_scope)
                    || name.starts_with('<')
                    || self.arity(id) != 0
                    || !self.is_unique(id)
                    || !self.returns.iter().any(|(s, _)| *s == id)
                {
                    continue;
                }
                returned.push((name, self.returns_of(id, &mut context())));
            }
            for (name, location) in self
                .properties
                .get(&constant.enum_scope)
                .into_iter()
                .flatten()
            {
                let returns =
                    self.variable(constant.enum_scope, name, false, *location, &mut context());
                returned.push((name, returns));
            }
            for (name, returns) in returned {
                if !returns.is_empty() {
                    summaries.push(MethodSummary {
                        owner: owner.clone(),
                        name: name.to_owned(),
                        arity: 0,
                        return_type: None,
                        returns,
                    });
                }
            }
        }
        summaries.sort_by(|a, b| (&a.owner, &a.name).cmp(&(&b.owner, &b.name)));
        summaries
    }

    /// The constructor an enum constant with `arity` arguments calls: a
    /// declared one, or the primary constructor (Kotlin), whose parameters
    /// are the type's own.
    fn constructor_of(&self, enum_scope: ScopeId, arity: usize) -> Option<ScopeId> {
        let name = self.unit.scope(enum_scope).name.as_deref()?;
        match self.methods_of(Some(enum_scope), name, arity).as_slice() {
            [constructor] => Some(*constructor),
            [] if self.params.get(&enum_scope).map(Vec::len) == Some(arity) => Some(enum_scope),
            _ => None,
        }
    }
}
