//! Data flow within one file, in phase two: the values an argument may hold
//! when it is not a literal or constant, each with the path it takes.
//!
//! A variable's values come from its assignments (initializer included); a
//! parameter's from the calls to its method; a call's from the method's
//! `return`s, with the method's parameters bound to that call's arguments.
//! Concatenations combine their parts, conditionals (`?:`, `switch`, `if`,
//! `when`) offer each branch. What depends on other files is left as
//! [`ArgValue::Param`] and [`ArgValue::Returns`] candidates, and each method
//! that returns something publishes a [`MethodSummary`]: `shorwatch_core::link`
//! connects them across the project.
//!
//! Bounded and otherwise context-insensitive: when in doubt (an overloaded
//! method, too many combinations, a cycle) a value stays unknown rather than
//! invented.

use shorwatch_core::ir::{
    Arg, ArgValue, Candidate, ConstantDecl, FlowStep, Location, MethodSummary, ScopeId, ScopeKind,
    TypeRef,
};

use super::{ArgSource, Assignment, JvmFile, PendingArg};

/// How many assignments, calls and returns a path may go through.
const MAX_DEPTH: usize = 6;
/// How many values an argument may have before it is considered unknown.
const MAX_CANDIDATES: usize = 16;

/// A resolution in progress: what it is in the middle of, to stop at cycles
/// and depth, and the calls it entered, so that a parameter takes the value
/// of *that* call rather than of every call to the method.
#[derive(Default)]
struct Context<'a> {
    trail: Vec<(ScopeId, String)>,
    calls: Vec<Entered<'a>>,
}

/// A call whose callee's `return`s are being resolved.
struct Entered<'a> {
    method: ScopeId,
    args: &'a [PendingArg],
    scope: ScopeId,
}

impl JvmFile {
    /// The values `arg` may hold, as an [`ArgValue::OneOf`], or `None` when
    /// none is known.
    pub(super) fn flow_value(&self, arg: &PendingArg, scope: ScopeId) -> Option<ArgValue> {
        let candidates = self.candidates(arg, scope, &mut Context::default());
        (!candidates.is_empty()).then_some(ArgValue::OneOf(candidates))
    }

    /// What each method of this file that returns something returns, for
    /// calls from other files.
    pub(super) fn summaries(&self) -> Vec<MethodSummary> {
        let mut summaries = Vec::new();
        for (index, scope) in self.unit.scopes().iter().enumerate() {
            let Ok(id) = u32::try_from(index).map(ScopeId) else {
                continue;
            };
            let (Some(name), Some(owner)) = (scope.name.as_deref(), self.owner(id)) else {
                continue;
            };
            let arity = self.arity(id);
            if scope.kind != ScopeKind::Method || name.starts_with('<') || !self.is_unique(id) {
                continue;
            }
            let return_type = self
                .return_types
                .get(&id)
                .filter(|ty| is_object_type(ty))
                .map(|ty| self.type_ref(ty));
            let returns = if self.returns.iter().any(|(s, _)| *s == id) {
                self.returns_of(id, &mut Context::default())
            } else {
                Vec::new()
            };
            if return_type.is_some() || !returns.is_empty() {
                summaries.push(MethodSummary {
                    owner,
                    name: name.to_owned(),
                    arity,
                    return_type,
                    returns,
                });
            }
        }
        summaries
    }

    fn candidates<'a>(
        &'a self,
        arg: &'a PendingArg,
        scope: ScopeId,
        cx: &mut Context<'a>,
    ) -> Vec<Candidate> {
        if cx.trail.len() >= MAX_DEPTH {
            return Vec::new();
        }
        let found = match &arg.source {
            ArgSource::Value(ArgValue::Unknown) => Vec::new(),
            ArgSource::Value(value) => vec![Candidate {
                value: value.clone(),
                flow: vec![step(arg.location, format!("{} is written here", arg.raw))],
            }],
            ArgSource::Name(name) => match self.static_imports.get(name) {
                // A statically imported constant of another file.
                Some(owner) if self.lookup_scope(scope, name).is_none() => vec![Candidate {
                    value: ArgValue::Constant {
                        owner: TypeRef::qualified(owner.clone()),
                        name: name.clone(),
                    },
                    flow: vec![step(arg.location, format!("{name} is a constant"))],
                }],
                _ => self.variable(scope, name, false, arg.location, cx),
            },
            ArgSource::Member { owner, name } if owner == "this" => {
                self.variable(scope, name, true, arg.location, cx)
            }
            ArgSource::Member { owner, name } => {
                let note = format!("{owner}.{name} is a constant");
                let value = self
                    .member_constant(scope, owner, name)
                    .or_else(|| self.foreign_constant(scope, owner, name));
                value
                    .map(|value| {
                        vec![Candidate {
                            value,
                            flow: vec![step(arg.location, note)],
                        }]
                    })
                    .unwrap_or_default()
            }
            ArgSource::Concat(parts) => self.concat(parts, scope, cx),
            ArgSource::Choice(options) => options
                .iter()
                .flat_map(|option| self.candidates(option, scope, cx))
                .collect(),
            ArgSource::Call { method, args } => self.call(method, args, scope, cx),
            // Another type's method: `link` looks up what it returns.
            ArgSource::MemberCall {
                receiver,
                method,
                args,
            } => match self.resolve_receiver(receiver, scope) {
                Some(owner) => vec![Candidate {
                    value: ArgValue::Returns {
                        owner,
                        method: method.clone(),
                        args: self.call_args(args, scope, cx),
                    },
                    flow: Vec::new(),
                }],
                None => Vec::new(),
            },
        };
        let mut unique: Vec<Candidate> = Vec::new();
        for candidate in found {
            if !unique.iter().any(|u| u.value == candidate.value) {
                unique.push(candidate);
            }
        }
        if unique.len() > MAX_CANDIDATES {
            return Vec::new();
        }
        unique
    }

    /// `Owner.NAME` where `Owner` is a type of another file: a constant for
    /// `link` to look up. Not when `Owner` is a variable.
    fn foreign_constant(&self, scope: ScopeId, owner: &str, name: &str) -> Option<ArgValue> {
        let first = owner.split('.').next().unwrap_or(owner);
        if matches!(first, "this" | "super")
            || self.lookup_scope(scope, first).is_some()
            || !owner.split('.').any(super::starts_uppercase)
        {
            return None;
        }
        Some(ArgValue::Constant {
            owner: self.type_ref(owner),
            name: name.to_owned(),
        })
    }

    /// Constants of this file's types, for other files.
    pub(super) fn constants(&self) -> Vec<ConstantDecl> {
        let mut constants: Vec<ConstantDecl> = self
            .symbols
            .iter()
            .filter(|((scope, _), _)| self.unit.scope(*scope).kind == ScopeKind::Type)
            .filter_map(|((scope, name), symbol)| {
                let value = symbol.constant.clone()?;
                matches!(value, ArgValue::Str(_) | ArgValue::Int(_)).then_some(())?;
                Some(ConstantDecl {
                    owner: self.owner(*scope)?,
                    name: name.clone(),
                    value,
                })
            })
            .collect();
        constants.sort_by(|a, b| (&a.owner, &a.name).cmp(&(&b.owner, &b.name)));
        constants
    }

    /// The arguments of a call to another file's method, resolved within the
    /// resolution in progress (its bounds and cycle checks apply).
    fn call_args<'a>(
        &'a self,
        args: &'a [PendingArg],
        scope: ScopeId,
        cx: &mut Context<'a>,
    ) -> Vec<Arg> {
        args.iter()
            .map(|arg| {
                let (value, resolved_via) = match &arg.source {
                    ArgSource::Value(value) => (value.clone(), None),
                    _ => {
                        let candidates = self.candidates(arg, scope, cx);
                        if candidates.is_empty() {
                            (ArgValue::Unknown, None)
                        } else {
                            (ArgValue::OneOf(candidates), Some(arg.raw.clone()))
                        }
                    }
                };
                Arg {
                    value,
                    raw: arg.raw.clone(),
                    resolved_via,
                    location: arg.location,
                }
            })
            .collect()
    }

    /// A local variable, parameter or field (`this.name` when `field`),
    /// referred to at `at`.
    fn variable<'a>(
        &'a self,
        scope: ScopeId,
        name: &str,
        field: bool,
        at: Location,
        cx: &mut Context<'a>,
    ) -> Vec<Candidate> {
        let declared = if field {
            self.enclosing_type(scope)
                .filter(|t| self.symbols.contains_key(&(*t, name.to_owned())))
        } else {
            self.lookup_scope(scope, name)
        };
        let Some(declared) = declared else {
            return Vec::new();
        };
        let key = (declared, name.to_owned());
        if cx.trail.contains(&key) {
            return Vec::new();
        }
        if let Some(value) = &self.symbols[&key].constant {
            let note = match value {
                ArgValue::Injected { key, .. } => format!("{name} is injected from ${{{key}}}"),
                _ => format!("{name} is a constant"),
            };
            return vec![Candidate {
                value: value.clone(),
                flow: vec![step(at, note)],
            }];
        }
        cx.trail.push(key);
        let mut found = Vec::new();
        for assignment in self.assignments.iter().filter(|a| a.name == name) {
            if self.assignment_target(assignment) != Some(declared) {
                continue;
            }
            for mut candidate in self.candidates(&assignment.value, assignment.scope, cx) {
                candidate
                    .flow
                    .push(step(assignment.location, format!("assigned to {name}")));
                found.push(candidate);
            }
        }
        let index = self
            .params
            .get(&declared)
            .and_then(|params| params.iter().position(|p| p == name));
        if let Some(index) = index {
            found.extend(self.parameter(declared, name, index, cx));
        }
        cx.trail.pop();
        found
    }

    /// Parameter `index` of `method`: the argument of the call being
    /// resolved, if any; otherwise every call in this file, and, for `link`,
    /// the calls from other files.
    fn parameter<'a>(
        &'a self,
        method: ScopeId,
        param: &str,
        index: usize,
        cx: &mut Context<'a>,
    ) -> Vec<Candidate> {
        let Some(name) = self.unit.scope(method).name.as_deref() else {
            return Vec::new();
        };
        let arity = self.arity(method);
        // A type's own parameters are its primary constructor's (Kotlin).
        let constructor = self.unit.scope(method).kind == ScopeKind::Type;
        if !constructor && !self.is_unique(method) {
            return Vec::new();
        }
        let note = format!("passed as {param} to {name}(...)");
        if let Some(position) = cx.calls.iter().rposition(|c| c.method == method) {
            // The caller's argument is resolved where the caller is.
            let inner = cx.calls.split_off(position);
            let (args, scope) = (inner[0].args, inner[0].scope);
            let found = self.candidates(&args[index], scope, cx);
            cx.calls.extend(inner);
            return then(found, args[index].location, &note);
        }
        let mut found = Vec::new();
        for call in &self.local_calls {
            if call.method == name
                && call.args.len() == arity
                && self.target(call.scope, name, arity) == Some(method)
            {
                let arg = &call.args[index];
                let candidates = self.candidates(arg, call.scope, cx);
                found.extend(then(candidates, arg.location, &note));
            }
        }
        if let Some(owner) = self.owner(method) {
            found.push(Candidate {
                value: ArgValue::Param {
                    owner,
                    method: name.to_owned(),
                    arity,
                    index,
                    param: param.to_owned(),
                },
                flow: Vec::new(),
            });
        }
        found
    }

    /// `name(args)`: what the method of this file returns for these
    /// arguments.
    fn call<'a>(
        &'a self,
        name: &str,
        args: &'a [PendingArg],
        scope: ScopeId,
        cx: &mut Context<'a>,
    ) -> Vec<Candidate> {
        let Some(method) = self.target(scope, name, args.len()) else {
            return Vec::new();
        };
        cx.calls.push(Entered {
            method,
            args,
            scope,
        });
        let found = self.returns_of(method, cx);
        cx.calls.pop();
        found
    }

    /// The values `method`'s `return`s may hold.
    fn returns_of<'a>(&'a self, method: ScopeId, cx: &mut Context<'a>) -> Vec<Candidate> {
        let key = (method, "<return>".to_owned());
        if cx.trail.contains(&key) {
            return Vec::new();
        }
        let name = self.unit.scope(method).name.clone().unwrap_or_default();
        cx.trail.push(key);
        let mut found = Vec::new();
        for (scope, value) in self.returns.iter().filter(|(scope, _)| *scope == method) {
            for mut candidate in self.candidates(value, *scope, cx) {
                candidate
                    .flow
                    .push(step(value.location, format!("returned by {name}(...)")));
                found.push(candidate);
            }
        }
        cx.trail.pop();
        found
    }

    /// Every combination of the parts' values, as long as one part at least
    /// is a string (`KEY_BITS + 1` is not a concatenation).
    fn concat<'a>(
        &'a self,
        parts: &'a [PendingArg],
        scope: ScopeId,
        cx: &mut Context<'a>,
    ) -> Vec<Candidate> {
        let mut combinations = vec![(String::new(), Vec::new())];
        let mut has_string = false;
        for part in parts {
            let candidates = self.candidates(part, scope, cx);
            let values: Vec<(String, &[FlowStep])> = candidates
                .iter()
                .flat_map(|c| {
                    has_string |= !matches!(c.value, ArgValue::Int(_));
                    // A literal part is visible where it is used: no step.
                    let flow = if matches!(part.source, ArgSource::Value(_)) {
                        &[][..]
                    } else {
                        &c.flow[..]
                    };
                    c.value.texts().into_iter().map(move |text| (text, flow))
                })
                .collect();
            if values.is_empty() || combinations.len() * values.len() > MAX_CANDIDATES {
                return Vec::new();
            }
            combinations = combinations
                .iter()
                .flat_map(|(prefix, flow)| {
                    values.iter().map(move |(text, steps)| {
                        let mut flow: Vec<FlowStep> = Vec::clone(flow);
                        flow.extend(steps.iter().cloned());
                        (format!("{prefix}{text}"), flow)
                    })
                })
                .collect();
        }
        if !has_string {
            return Vec::new();
        }
        combinations
            .into_iter()
            .map(|(text, flow)| Candidate {
                value: ArgValue::Str(text),
                flow,
            })
            .collect()
    }

    /// The scope that declares the variable `assignment` writes.
    fn assignment_target(&self, assignment: &Assignment) -> Option<ScopeId> {
        if assignment.field {
            self.enclosing_type(assignment.scope)
                .filter(|t| self.symbols.contains_key(&(*t, assignment.name.clone())))
        } else {
            self.lookup_scope(assignment.scope, &assignment.name)
        }
    }

    /// The method an unqualified call `name(..arity)` in `scope` targets:
    /// the innermost enclosing type that declares one, if it declares only
    /// one (no overload).
    fn target(&self, scope: ScopeId, name: &str, arity: usize) -> Option<ScopeId> {
        let mut owner = self.enclosing_type(scope);
        loop {
            let methods = self.methods_of(owner, name, arity);
            match methods.as_slice() {
                [method] => return Some(*method),
                [] => {}
                _ => return None,
            }
            let ty = owner?;
            owner = self
                .unit
                .scope(ty)
                .parent
                .and_then(|p| self.enclosing_type(p));
        }
    }

    /// Whether `method` is its type's only method with its name and arity.
    fn is_unique(&self, method: ScopeId) -> bool {
        let name = self.unit.scope(method).name.as_deref().unwrap_or_default();
        let owner = self.enclosing_type(method);
        self.methods_of(owner, name, self.arity(method)) == [method]
    }

    /// The methods named `name` with `arity` parameters declared directly in
    /// `owner` (top-level functions when `None`).
    fn methods_of(&self, owner: Option<ScopeId>, name: &str, arity: usize) -> Vec<ScopeId> {
        self.method_scopes
            .get(&(owner, name.to_owned(), arity))
            .cloned()
            .unwrap_or_default()
    }

    /// Indexes type and method scopes for [`Self::methods_of`] and type
    /// lookups, once the traversal has declared them all.
    pub(super) fn index_scopes(&mut self) {
        for (index, scope) in self.unit.scopes().iter().enumerate() {
            let (Ok(id), Some(name)) = (u32::try_from(index).map(ScopeId), scope.name.as_deref())
            else {
                continue;
            };
            match scope.kind {
                ScopeKind::Type => self
                    .type_scopes
                    .entry(name.to_owned())
                    .or_default()
                    .push(id),
                ScopeKind::Method => {
                    let key = (self.enclosing_type(id), name.to_owned(), self.arity(id));
                    self.method_scopes.entry(key).or_default().push(id);
                }
                ScopeKind::File => {}
            }
        }
    }

    fn arity(&self, method: ScopeId) -> usize {
        self.params.get(&method).map_or(0, Vec::len)
    }

    /// The fully qualified type that declares `scope`: package, then the
    /// enclosing types (`com.acme.Outer.Inner`). `None` outside any type.
    pub(super) fn owner(&self, scope: ScopeId) -> Option<String> {
        let mut types = Vec::new();
        let mut current = Some(scope);
        while let Some(id) = current {
            let scope = self.unit.scope(id);
            if scope.kind == ScopeKind::Type {
                types.push(scope.name.clone()?);
            }
            current = scope.parent;
        }
        if types.is_empty() {
            return None;
        }
        types.reverse();
        let path = types.join(".");
        Some(if self.package.is_empty() {
            path
        } else {
            format!("{}.{path}", self.package)
        })
    }

    fn enclosing_type(&self, mut scope: ScopeId) -> Option<ScopeId> {
        loop {
            if self.unit.scope(scope).kind == ScopeKind::Type {
                return Some(scope);
            }
            scope = self.unit.scope(scope).parent?;
        }
    }
}

/// Whether a declared return type can type a chained receiver: a class of
/// its own, not a primitive, `String` or a JDK value type.
fn is_object_type(ty: &str) -> bool {
    const VALUE_TYPES: &[&str] = &[
        "String",
        "Object",
        "Boolean",
        "Byte",
        "Short",
        "Integer",
        "Long",
        "Float",
        "Double",
        "Character",
        "Void",
        "Any",
        "Unit",
        "Int",
        "Char",
        "ByteArray",
    ];
    ty.chars().next().is_some_and(char::is_uppercase) && !VALUE_TYPES.contains(&ty)
}

/// The candidates, each with one more step.
fn then(candidates: Vec<Candidate>, location: Location, note: &str) -> Vec<Candidate> {
    candidates
        .into_iter()
        .map(|mut candidate| {
            candidate.flow.push(step(location, note.to_owned()));
            candidate
        })
        .collect()
}

fn step(location: Location, note: String) -> FlowStep {
    FlowStep {
        path: None,
        location,
        note,
    }
}
