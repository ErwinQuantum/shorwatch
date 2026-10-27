//! Data flow across files. Frontends resolve what they can within a file and
//! leave two kinds of candidates for the rest: [`ArgValue::Param`] (a
//! parameter whose value comes from calls elsewhere) and
//! [`ArgValue::Returns`] (a call to another type's method). Here they are
//! replaced by the values they stand for, found in the calls and
//! [`MethodSummary`]s of every unit, and each step of the path records the
//! file it is in.
//!
//! Methods are matched by name and arity, and by type through the project's
//! hierarchy: a call through an interface reaches every implementation.
//! Overloads (several methods of a type with one name and arity) stay
//! unknown; frontends publish no summary for them. A parameter of a method being
//! called takes that call's argument; otherwise every call counts. Production
//! code only takes values from production code.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use super::args;
use super::hierarchy::Hierarchy;
use crate::ir::{Arg, ArgValue, Candidate, CodeRole, FactKind, FlowStep, SourceUnit, TypeRef};

/// How many calls between files a path may cross.
const MAX_HOPS: usize = 3;
/// How many values an argument keeps.
const MAX_CANDIDATES: usize = 32;

/// Replaces the cross-file candidates of every argument by what they stand
/// for. Values that cannot be found are dropped.
pub(super) fn resolve(units: &mut [SourceUnit], hierarchy: &Hierarchy) {
    let replacements = {
        let project = Project::of(units, hierarchy);
        let mut replacements = Vec::new();
        for (u, unit) in units.iter().enumerate() {
            for (f, fact) in unit.facts().iter().enumerate() {
                for (a, arg) in args(&fact.kind).into_iter().enumerate() {
                    if let ArgValue::OneOf(candidates) = &arg.value
                        && candidates.iter().any(is_cross_file)
                    {
                        let value = project.resolve(candidates, unit.path(), unit.role());
                        replacements.push((u, f, a, value));
                    }
                }
            }
        }
        replacements
    };
    for (u, f, a, value) in replacements {
        if let Some(arg) = super::args_mut(&mut units[u].facts[f].kind)
            .into_iter()
            .nth(a)
        {
            arg.value = value;
        }
    }
}

fn is_cross_file(candidate: &Candidate) -> bool {
    matches!(
        candidate.value,
        ArgValue::Param { .. } | ArgValue::Returns { .. } | ArgValue::Constant { .. }
    )
}

/// A call through a project type.
struct Call<'u> {
    path: &'u str,
    role: CodeRole,
    args: &'u [Arg],
}

/// A method that returns something.
struct Method<'u> {
    path: &'u str,
    role: CodeRole,
    owner: &'u str,
    returns: &'u [Candidate],
}

/// Calls and methods of every unit, by method name, arity and the project
/// type they are called through or declared in. Calls through other types
/// (the JDK, libraries) cannot reach the project's methods and are left out.
struct Project<'u> {
    calls: HashMap<(&'u str, usize, &'u str), Vec<Call<'u>>>,
    methods: HashMap<(&'u str, usize, &'u str), Vec<Method<'u>>>,
    /// Constants by declaring type and name.
    constants: HashMap<(&'u str, &'u str), &'u ArgValue>,
    hierarchy: &'u Hierarchy,
    /// A parameter's values, with every step's file explicit, by parameter,
    /// role and hops left: many arguments may wait for the same parameter.
    params: RefCell<HashMap<ParamKey, Vec<Candidate>>>,
}

type ParamKey = (String, String, usize, usize, CodeRole, usize);

impl<'u> Project<'u> {
    fn of(units: &'u [SourceUnit], hierarchy: &'u Hierarchy) -> Self {
        let mut calls: HashMap<_, Vec<_>> = HashMap::new();
        let mut methods: HashMap<_, Vec<_>> = HashMap::new();
        let mut constants = HashMap::new();
        for unit in units {
            for constant in unit.constants() {
                constants.insert(
                    (constant.owner.as_str(), constant.name.as_str()),
                    &constant.value,
                );
            }
            for fact in unit.facts() {
                // A constructor is a method named after its type.
                let (receiver, method, args) = match &fact.kind {
                    FactKind::Call {
                        receiver: Some(receiver),
                        method,
                        args,
                        ..
                    } => (receiver, method.as_str(), args),
                    FactKind::Construct { ty, args } => {
                        (ty, ty.name.rsplit('.').next().unwrap_or(&ty.name), args)
                    }
                    _ => continue,
                };
                // A qualified type no unit declares still names itself.
                let mut types = hierarchy.declared(receiver);
                if types.is_empty()
                    && let Some(qualified) = &receiver.qualified
                {
                    types.push(qualified);
                }
                for ty in types {
                    calls
                        .entry((method, args.len(), ty))
                        .or_default()
                        .push(Call {
                            path: unit.path(),
                            role: unit.role(),
                            args,
                        });
                }
            }
            for summary in unit.methods().iter().filter(|m| !m.returns.is_empty()) {
                methods
                    .entry((summary.name.as_str(), summary.arity, summary.owner.as_str()))
                    .or_default()
                    .push(Method {
                        path: unit.path(),
                        role: unit.role(),
                        owner: &summary.owner,
                        returns: &summary.returns,
                    });
            }
        }
        Self {
            calls,
            methods,
            constants,
            hierarchy,
            params: RefCell::default(),
        }
    }

    /// The candidates of an argument of a unit at `here`, with the
    /// cross-file ones expanded.
    fn resolve(&self, candidates: &[Candidate], here: &str, role: CodeRole) -> ArgValue {
        let mut unique: Vec<Candidate> = Vec::new();
        for candidate in candidates {
            for expanded in self.expand(candidate, here, role, MAX_HOPS) {
                if unique.len() < MAX_CANDIDATES
                    && !unique.iter().any(|u| u.value == expanded.value)
                {
                    unique.push(expanded);
                }
            }
        }
        if unique.is_empty() {
            ArgValue::Unknown
        } else {
            ArgValue::OneOf(unique)
        }
    }

    /// What `candidate`, found in the unit at `here`, stands for. Steps
    /// without a path are in `here`.
    fn expand(
        &self,
        candidate: &Candidate,
        here: &str,
        role: CodeRole,
        hops: usize,
    ) -> Vec<Candidate> {
        let found = match &candidate.value {
            _ if hops == 0 && is_cross_file(candidate) => Vec::new(),
            ArgValue::Param {
                owner,
                method,
                arity,
                index,
                param,
            } => {
                let key = (owner.clone(), method.clone(), *arity, *index, role, hops);
                let cached = self.params.borrow().get(&key).cloned();
                let found = cached.unwrap_or_else(|| {
                    let found = self.parameter(owner, method, *arity, *index, param, role, hops);
                    self.params.borrow_mut().insert(key, found.clone());
                    found
                });
                // Cached with every file explicit: `here`'s own steps lose it.
                found
                    .into_iter()
                    .map(|mut c| {
                        for step in &mut c.flow {
                            if step.path.as_deref() == Some(here) {
                                step.path = None;
                            }
                        }
                        c
                    })
                    .collect()
            }
            ArgValue::Returns {
                owner,
                method,
                args,
            } => self.returns(owner, method, args, here, role, hops),
            // Declared by the type or one of its supertypes.
            ArgValue::Constant { owner, name } => self
                .hierarchy
                .declared(owner)
                .into_iter()
                .flat_map(|ty| self.hierarchy.with_ancestors(ty))
                .find_map(|ty| self.constants.get(&(ty, name.as_str())))
                .map(|value| {
                    vec![Candidate {
                        value: (*value).clone(),
                        flow: Vec::new(),
                    }]
                })
                .unwrap_or_default(),
            _ => return vec![candidate.clone()],
        };
        found
            .into_iter()
            .map(|mut c| {
                c.flow.extend(candidate.flow.iter().cloned());
                c
            })
            .collect()
    }

    /// The values the calls of the project pass as parameter `index` of
    /// `owner.method`, through any related type, with every step's file.
    #[allow(clippy::too_many_arguments)]
    fn parameter(
        &self,
        owner: &str,
        method: &str,
        arity: usize,
        index: usize,
        param: &str,
        role: CodeRole,
        hops: usize,
    ) -> Vec<Candidate> {
        let note = format!("passed as {param} to {method}(...)");
        let mut found = Vec::new();
        for ty in self.hierarchy.related(owner) {
            for call in self.calls.get(&(method, arity, ty)).into_iter().flatten() {
                if !visible(call.role, role) {
                    continue;
                }
                let arg = &call.args[index];
                for origin in self.origins(arg, call.path, role, hops - 1) {
                    let mut flow = moved(origin.flow, call.path, "");
                    flow.push(FlowStep {
                        path: Some(call.path.to_owned()),
                        location: arg.location,
                        note: note.clone(),
                    });
                    found.push(Candidate {
                        value: origin.value,
                        flow,
                    });
                    if found.len() >= MAX_CANDIDATES {
                        return found;
                    }
                }
            }
        }
        found
    }

    /// What `owner.method(args)`, called in `here`, returns: any method it
    /// may reach through the hierarchy.
    fn returns(
        &self,
        owner: &TypeRef,
        method: &str,
        args: &[Arg],
        here: &str,
        role: CodeRole,
        hops: usize,
    ) -> Vec<Candidate> {
        // Through an interface, any implementation may answer.
        let owners: HashSet<&str> = self
            .hierarchy
            .declared(owner)
            .into_iter()
            .flat_map(|declared| self.hierarchy.related(declared))
            .collect();
        let callees = owners
            .into_iter()
            .flat_map(|o| {
                self.methods
                    .get(&(method, args.len(), o))
                    .into_iter()
                    .flatten()
            })
            .filter(|m| visible(m.role, role));
        let mut found = Vec::new();
        for (callee, returned) in callees.flat_map(|c| c.returns.iter().map(move |r| (c, r))) {
            let origins: Vec<Candidate> = match &returned.value {
                // The callee's own parameter: this call's argument.
                ArgValue::Param {
                    owner,
                    method: m,
                    arity,
                    index,
                    param,
                } if owner == callee.owner && m == method && *arity == args.len() => {
                    let arg = &args[*index];
                    self.origins(arg, here, role, hops - 1)
                        .into_iter()
                        .map(|mut origin| {
                            origin.flow.push(FlowStep {
                                path: None,
                                location: arg.location,
                                note: format!("passed as {param} to {method}(...)"),
                            });
                            origin
                                .flow
                                .extend(moved(returned.flow.clone(), callee.path, here));
                            origin
                        })
                        .collect()
                }
                _ => self
                    .expand(returned, callee.path, role, hops - 1)
                    .into_iter()
                    .map(|mut origin| {
                        origin.flow = moved(origin.flow, callee.path, here);
                        origin
                    })
                    .collect(),
            };
            found.extend(origins);
        }
        found
    }

    /// The values `arg`, an argument in the unit at `path`, may hold. Steps
    /// without a path are in `path`.
    fn origins(&self, arg: &Arg, path: &str, role: CodeRole, hops: usize) -> Vec<Candidate> {
        match &arg.value {
            ArgValue::Unknown
            | ArgValue::Param { .. }
            | ArgValue::Returns { .. }
            | ArgValue::Constant { .. } => Vec::new(),
            ArgValue::OneOf(candidates) => candidates
                .iter()
                .flat_map(|c| self.expand(c, path, role, hops))
                .collect(),
            value => {
                let note = match (value, &arg.resolved_via) {
                    (ArgValue::Injected { key, .. }, _) => {
                        format!("{} is injected from ${{{key}}}", arg.raw)
                    }
                    (_, Some(via)) => format!("{via} is a constant"),
                    _ => format!("{} is written here", arg.raw),
                };
                vec![Candidate {
                    value: value.clone(),
                    flow: vec![FlowStep {
                        path: None,
                        location: arg.location,
                        note,
                    }],
                }]
            }
        }
    }
}

/// Whether code with role `of` may feed values to code with role `to`.
fn visible(of: CodeRole, to: CodeRole) -> bool {
    to == CodeRole::Test || of == CodeRole::Production
}

/// `path`, unless it is `here`.
fn elsewhere(path: &str, here: &str) -> Option<String> {
    (path != here).then(|| path.to_owned())
}

/// Steps recorded relative to the unit at `from`, made relative to `here`.
fn moved(flow: Vec<FlowStep>, from: &str, here: &str) -> Vec<FlowStep> {
    flow.into_iter()
        .map(|mut step| {
            let path = step.path.take().unwrap_or_else(|| from.to_owned());
            step.path = elsewhere(&path, here);
            step
        })
        .collect()
}
