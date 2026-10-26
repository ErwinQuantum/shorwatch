//! Data flow across files. Frontends resolve what they can within a file and
//! leave two kinds of candidates for the rest: [`ArgValue::Param`] (a
//! parameter whose value comes from calls elsewhere) and
//! [`ArgValue::Returns`] (a call to another type's method). Here they are
//! replaced by the values they stand for, found in the calls and
//! [`MethodSummary`]s of every unit, and each step of the path records the
//! file it is in.
//!
//! Methods are matched by declaring type, name and arity, constructors by
//! type and arity: an overload, or a call through an interface, stays
//! unknown. A parameter of a method being
//! called takes that call's argument; otherwise every call counts. Production
//! code only takes values from production code.

use std::collections::HashMap;

use super::args;
use crate::ir::{Arg, ArgValue, Candidate, CodeRole, FactKind, FlowStep, SourceUnit, TypeRef};

/// How many calls between files a path may cross.
const MAX_HOPS: usize = 3;
/// How many values an argument keeps.
const MAX_CANDIDATES: usize = 32;

/// Replaces the cross-file candidates of every argument by what they stand
/// for. Values that cannot be found are dropped.
pub(super) fn resolve(units: &mut [SourceUnit]) {
    let replacements = {
        let project = Project::of(units);
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
        ArgValue::Param { .. } | ArgValue::Returns { .. }
    )
}

/// A call whose receiver has a known type.
struct Call<'u> {
    path: &'u str,
    role: CodeRole,
    receiver: &'u TypeRef,
    args: &'u [Arg],
}

/// A method that returns something.
struct Method<'u> {
    path: &'u str,
    role: CodeRole,
    owner: &'u str,
    returns: &'u [Candidate],
}

/// Calls and methods of every unit, by method name and arity.
struct Project<'u> {
    calls: HashMap<(&'u str, usize), Vec<Call<'u>>>,
    methods: HashMap<(&'u str, usize), Vec<Method<'u>>>,
}

impl<'u> Project<'u> {
    fn of(units: &'u [SourceUnit]) -> Self {
        let mut calls: HashMap<_, Vec<_>> = HashMap::new();
        let mut methods: HashMap<_, Vec<_>> = HashMap::new();
        for unit in units {
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
                calls.entry((method, args.len())).or_default().push(Call {
                    path: unit.path(),
                    role: unit.role(),
                    receiver,
                    args,
                });
            }
            for summary in unit.methods() {
                methods
                    .entry((summary.name.as_str(), summary.arity))
                    .or_default()
                    .push(Method {
                        path: unit.path(),
                        role: unit.role(),
                        owner: &summary.owner,
                        returns: &summary.returns,
                    });
            }
        }
        Self { calls, methods }
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
                let note = format!("passed as {param} to {method}(...)");
                let mut found = Vec::new();
                for call in self
                    .calls
                    .get(&(method.as_str(), *arity))
                    .into_iter()
                    .flatten()
                {
                    if !call.receiver.is(owner) || !visible(call.role, role) {
                        continue;
                    }
                    let arg = &call.args[*index];
                    for origin in self.origins(arg, call.path, role, hops - 1) {
                        let mut flow = moved(origin.flow, call.path, here);
                        flow.push(FlowStep {
                            path: elsewhere(call.path, here),
                            location: arg.location,
                            note: note.clone(),
                        });
                        found.push(Candidate {
                            value: origin.value,
                            flow,
                        });
                    }
                }
                found
            }
            ArgValue::Returns {
                owner,
                method,
                args,
            } => self.returns(owner, method, args, here, role, hops),
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

    /// What `owner.method(args)`, called in `here`, returns.
    fn returns(
        &self,
        owner: &TypeRef,
        method: &str,
        args: &[Arg],
        here: &str,
        role: CodeRole,
        hops: usize,
    ) -> Vec<Candidate> {
        let mut matching = self
            .methods
            .get(&(method, args.len()))
            .into_iter()
            .flatten()
            .filter(|m| owner.is(m.owner) && visible(m.role, role));
        let (Some(callee), None) = (matching.next(), matching.next()) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for returned in callee.returns {
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
            ArgValue::Unknown | ArgValue::Param { .. } | ArgValue::Returns { .. } => Vec::new(),
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
