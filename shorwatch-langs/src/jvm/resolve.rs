//! Phase two of a JVM lowering: once the whole file has been traversed,
//! pending facts are resolved. Receivers get their declared types, names
//! their constant or injected values, member imports their owners.

use super::{ArgSource, JvmFile, LocalCall, Pending, PendingArg, Receiver, starts_uppercase};
use shorwatch_core::Language;
use shorwatch_core::ir::{
    Arg, ArgValue, CallOwner, CallRef, FactKind, ScopeId, ScopeKind, SourceUnit, TypeDecl, TypeRef,
};

impl JvmFile {
    pub(crate) fn resolve(mut self) -> SourceUnit {
        self.index_scopes();
        self.local_calls = self
            .pending
            .iter()
            .filter_map(|(pending, scope, _)| match pending {
                // `m(...)` and `this.m(...)` have no receiver.
                Pending::Call {
                    receiver: None,
                    method,
                    args,
                } => Some(LocalCall {
                    scope: *scope,
                    method: method.clone(),
                    args: args.clone(),
                }),
                _ => None,
            })
            .collect();
        for (pending, scope, location) in std::mem::take(&mut self.pending) {
            let kind = match pending {
                Pending::Call {
                    receiver,
                    method,
                    args,
                } => FactKind::Call {
                    receiver_call: receiver.as_ref().and_then(|r| self.receiver_call(r, scope)),
                    receiver_origin: receiver
                        .as_ref()
                        .and_then(|r| self.receiver_origin(r, scope))
                        .map(|origin| self.resolve_args(origin, scope)),
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
        for summary in self.summaries() {
            self.unit.add_method(summary);
        }
        for constant in self.constants() {
            self.unit.add_constant(constant);
        }
        for (scope, supertypes) in std::mem::take(&mut self.type_decls) {
            if let Some(name) = self.owner(scope) {
                let supertypes = supertypes.iter().map(|s| self.type_ref(s)).collect();
                self.unit.add_type(TypeDecl { name, supertypes });
            }
        }
        self.unit
    }

    /// The call a receiver is the result of: written in place
    /// (`keys.provider().m()`) or the initializer of an untyped variable
    /// (`var p = keys.provider(); p.m()`), resolved where it was written.
    fn receiver_call(&self, receiver: &Receiver, scope: ScopeId) -> Option<CallRef> {
        let (call, scope) = match receiver {
            Receiver::Call { .. } => (receiver, scope),
            Receiver::Name(name) => self.initializer_call(name, scope)?,
            Receiver::Path(path) => {
                let field = path.strip_prefix("this.").filter(|f| !f.contains('.'))?;
                self.initializer_call(field, scope)?
            }
            Receiver::Type { .. } => return None,
        };
        let Receiver::Call {
            owner,
            method,
            arity,
        } = call
        else {
            return None;
        };
        self.call_ref(owner.as_deref(), method, *arity, scope)
    }

    fn initializer_call(&self, variable: &str, scope: ScopeId) -> Option<(&Receiver, ScopeId)> {
        let declared = self.lookup_scope(scope, variable)?;
        let symbol = self.symbols.get(&(declared, variable.to_owned()))?;
        Some((symbol.call.as_ref()?, declared))
    }

    /// `owner.method(..arity)`, the receiver of a chained call; `owner` may be
    /// a call itself (`a.b().c()`).
    fn call_ref(
        &self,
        owner: Option<&Receiver>,
        method: &str,
        arity: usize,
        scope: ScopeId,
    ) -> Option<CallRef> {
        let owner = match owner {
            Some(Receiver::Call {
                owner,
                method,
                arity,
            }) => CallOwner::Call(Box::new(self.call_ref(
                owner.as_deref(),
                method,
                *arity,
                scope,
            )?)),
            Some(receiver) => CallOwner::Type(self.resolve_receiver(receiver, scope)?),
            None => CallOwner::Type(TypeRef::qualified(self.owner(scope)?)),
        };
        Some(CallRef {
            owner,
            method: method.to_owned(),
            arity,
        })
    }

    pub(super) fn resolve_receiver(&self, receiver: &Receiver, scope: ScopeId) -> Option<TypeRef> {
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
            Receiver::Type { ty, .. } => Some(self.type_ref(ty)),
            // Typed by `link`, from the method's declared return type.
            Receiver::Call { .. } => None,
        }
    }

    /// Arguments of the factory call that created a receiver variable. Not
    /// data flow: only the variable's own initializer counts.
    fn receiver_origin(&self, receiver: &Receiver, scope: ScopeId) -> Option<Vec<PendingArg>> {
        let variable = match receiver {
            Receiver::Type { origin, .. } => return origin.clone(),
            Receiver::Name(name) => name.as_str(),
            Receiver::Path(path) => path.strip_prefix("this.").filter(|f| !f.contains('.'))?,
            Receiver::Call { .. } => return None,
        };
        self.lookup(scope, variable)?.origin.clone()
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
    pub(super) fn type_ref(&self, name: &str) -> TypeRef {
        match name.split_once('.') {
            // `java.security.KeyPairGenerator`: already fully qualified.
            Some((first, _)) if !starts_uppercase(first) => TypeRef::qualified(name),
            // `Outer.Inner`: qualified only if `Outer` was imported; otherwise
            // kept whole, so it is not mistaken for another type's `Inner`.
            Some((first, rest)) => match self.imports.get(first) {
                Some(outer) => TypeRef::qualified(format!("{outer}.{rest}")),
                None => self.unimported(name),
            },
            None => match self.imports.get(name) {
                Some(qualified) => TypeRef::qualified(qualified.clone()),
                None => self.unimported(name),
            },
        }
    }

    /// The fully qualified name of the only type of this file named `name`.
    fn local_type(&self, name: &str) -> Option<String> {
        match self.type_scopes.get(name)?.as_slice() {
            [scope] => self.owner(*scope),
            _ => None,
        }
    }

    /// A type name no import names: it can only come from the file's
    /// package, an on-demand import or the language's implicit imports.
    fn unimported(&self, name: &str) -> TypeRef {
        // A type of this file, nested ones included (`Signer` in `Outer`).
        if !name.contains('.')
            && let Some(local) = self.local_type(name)
        {
            return TypeRef::qualified(local);
        }
        if self.module_imports {
            return TypeRef::simple(name);
        }
        let implicit: &[&str] = match self.unit.language() {
            Language::Kotlin => &[
                "java.lang",
                "kotlin",
                "kotlin.annotation",
                "kotlin.collections",
                "kotlin.comparisons",
                "kotlin.io",
                "kotlin.jvm",
                "kotlin.ranges",
                "kotlin.sequences",
                "kotlin.text",
            ],
            _ => &["java.lang"],
        };
        let packages = std::iter::once(self.package.clone())
            .chain(self.on_demand_imports.iter().cloned())
            .chain(implicit.iter().map(|p| (*p).to_owned()))
            .collect();
        TypeRef::in_packages(name, packages)
    }

    fn resolve_args(&self, args: Vec<PendingArg>, scope: ScopeId) -> Vec<Arg> {
        args.into_iter()
            .map(|arg| {
                let (value, mut resolved_via) = match &arg.source {
                    ArgSource::Value(ArgValue::Unknown) => (None, None),
                    ArgSource::Value(value) => (Some(value.clone()), None),
                    ArgSource::Name(name) => (self.constant(scope, name), Some(name.clone())),
                    ArgSource::Member { owner, name } => (
                        self.member_constant(scope, owner, name),
                        Some(format!("{owner}.{name}")),
                    ),
                    ArgSource::Concat(_)
                    | ArgSource::Choice(_)
                    | ArgSource::Call { .. }
                    | ArgSource::MemberCall { .. } => (None, None),
                };
                if let Some(ArgValue::Injected { key, .. }) = &value {
                    resolved_via = Some(format!("${{{key}}}"));
                }
                // Not a literal or constant: maybe data flow knows.
                let value = value.or_else(|| {
                    let flowed = self.flow_value(&arg, scope)?;
                    resolved_via = Some(arg.raw.clone());
                    Some(flowed)
                });
                Arg {
                    resolved_via: value.as_ref().and(resolved_via),
                    value: value.unwrap_or(ArgValue::Unknown),
                    raw: arg.raw,
                    location: arg.location,
                }
            })
            .collect()
    }

    fn constant(&self, scope: ScopeId, name: &str) -> Option<ArgValue> {
        self.lookup(scope, name)?.constant.clone()
    }

    /// `Owner.NAME` or `this.NAME`, for owners declared in this file.
    pub(super) fn member_constant(
        &self,
        scope: ScopeId,
        owner: &str,
        name: &str,
    ) -> Option<ArgValue> {
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
