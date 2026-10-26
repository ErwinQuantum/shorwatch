//! Phase two of a JVM lowering: once the whole file has been traversed,
//! pending facts are resolved. Receivers get their declared types, names
//! their constant or injected values, member imports their owners.

use super::{ArgSource, JvmFile, Pending, PendingArg, Receiver, starts_uppercase};
use shorwatch_core::ir::{Arg, ArgValue, FactKind, ScopeId, ScopeKind, SourceUnit, TypeRef};

impl JvmFile {
    pub(crate) fn resolve(mut self) -> SourceUnit {
        for (pending, scope, location) in std::mem::take(&mut self.pending) {
            let kind = match pending {
                Pending::Call {
                    receiver,
                    method,
                    args,
                } => FactKind::Call {
                    receiver: match receiver {
                        Some(r) => self.resolve_receiver(&r, scope),
                        None => self.static_method_owner(&method),
                    },
                    method,
                    args: self.resolve_args(args, scope),
                },
                Pending::Construct { ty, args } => FactKind::Construct {
                    ty: self.type_ref(&ty),
                    args: self.resolve_args(args, scope),
                },
                Pending::Field { owner, name } => match self.field_owner(&owner, scope) {
                    Some(owner) => FactKind::Field { owner, name },
                    None => continue,
                },
                Pending::StaticMember(name) => {
                    if self.lookup(scope, &name).is_some() {
                        continue;
                    }
                    let owner = TypeRef::qualified(self.static_imports[&name].clone());
                    FactKind::Field { owner, name }
                }
                Pending::Ready(kind) => kind,
            };
            self.unit.push(kind, scope, location);
        }
        self.unit
    }

    fn resolve_receiver(&self, receiver: &Receiver, scope: ScopeId) -> Option<TypeRef> {
        let variable_type = |name: &str| {
            self.lookup(scope, name)
                .and_then(|s| s.ty.as_deref())
                .map(|ty| self.type_ref(ty))
        };
        match receiver {
            Receiver::Name(name) => {
                variable_type(name).or_else(|| starts_uppercase(name).then(|| self.type_ref(name)))
            }
            Receiver::Path(path) => match path.strip_prefix("this.") {
                Some(field) if !field.contains('.') => variable_type(field),
                Some(_) => None,
                None => Some(self.type_ref(path)),
            },
            Receiver::Type(ty) => Some(self.type_ref(ty)),
        }
    }

    /// Owner of an unqualified call such as `RSA256(...)`, when it comes from a
    /// static import and no method of this file shadows it.
    fn static_method_owner(&self, method: &str) -> Option<TypeRef> {
        if self.methods.contains(method) {
            return None;
        }
        self.static_imports
            .get(method)
            .map(|owner| TypeRef::qualified(owner.clone()))
    }

    /// The type named by `owner` in `owner.NAME`, or `None` when `owner` is a
    /// variable or `this`: then it is an instance field, not a static constant.
    fn field_owner(&self, owner: &str, scope: ScopeId) -> Option<TypeRef> {
        let first = owner.split('.').next().unwrap_or(owner);
        if matches!(first, "this" | "super") || self.lookup(scope, first).is_some() {
            return None;
        }
        owner
            .split('.')
            .any(starts_uppercase)
            .then(|| self.type_ref(owner))
    }

    /// Resolves a type name as written to the most precise [`TypeRef`] possible.
    fn type_ref(&self, name: &str) -> TypeRef {
        match name.split_once('.') {
            // `java.security.KeyPairGenerator`: already fully qualified.
            Some((first, _)) if !starts_uppercase(first) => TypeRef::qualified(name),
            // `Outer.Inner`: qualified only if `Outer` was imported.
            Some((first, rest)) => match self.imports.get(first) {
                Some(outer) => TypeRef::qualified(format!("{outer}.{rest}")),
                None => TypeRef::simple(name.rsplit('.').next().unwrap_or(name)),
            },
            None => match self.imports.get(name) {
                Some(qualified) => TypeRef::qualified(qualified.clone()),
                None => TypeRef::simple(name),
            },
        }
    }

    fn resolve_args(&self, args: Vec<PendingArg>, scope: ScopeId) -> Vec<Arg> {
        args.into_iter()
            .map(
                |PendingArg {
                     source,
                     raw,
                     location,
                 }| {
                    let (value, mut resolved_via) = match source {
                        ArgSource::Value(value) => (Some(value), None),
                        ArgSource::Name(name) => (self.constant(scope, &name), Some(name)),
                        ArgSource::Member { owner, name } => (
                            self.member_constant(scope, &owner, &name),
                            Some(format!("{owner}.{name}")),
                        ),
                    };
                    if let Some(ArgValue::Injected { key, .. }) = &value {
                        resolved_via = Some(format!("${{{key}}}"));
                    }
                    match value {
                        Some(value) => Arg {
                            value,
                            raw,
                            resolved_via,
                            location,
                        },
                        None => Arg {
                            value: ArgValue::Unknown,
                            raw,
                            resolved_via: None,
                            location,
                        },
                    }
                },
            )
            .collect()
    }

    fn constant(&self, scope: ScopeId, name: &str) -> Option<ArgValue> {
        self.lookup(scope, name)?.constant.clone()
    }

    /// `Owner.NAME` or `this.NAME`, for owners declared in this file.
    fn member_constant(&self, scope: ScopeId, owner: &str, name: &str) -> Option<ArgValue> {
        if owner == "this" {
            return self.constant(scope, name);
        }
        let owner = owner.rsplit('.').next().unwrap_or(owner);
        self.unit
            .scopes()
            .iter()
            .enumerate()
            .find_map(|(index, s)| {
                let id = ScopeId(u32::try_from(index).ok()?);
                if s.kind == ScopeKind::Type && s.name.as_deref() == Some(owner) {
                    self.symbols.get(&(id, name.to_owned()))?.constant.clone()
                } else {
                    None
                }
            })
    }
}
