//! Data flow within one file, in phase two: the values an argument may hold
//! when it is not a literal or constant, each with the path it takes.
//!
//! A variable's values come from its assignments (initializer included); a
//! parameter's from the calls to its method in this file; a call's from the
//! method's `return`s. Concatenations combine their parts, conditionals
//! (`?:`, `switch`, `if`, `when`) offer each branch. The analysis is
//! context-insensitive and bounded: when in doubt (an overloaded method, too
//! many combinations, a cycle) a value stays unknown rather than invented.

use shorwatch_core::ir::{ArgValue, Candidate, FlowStep, Location, ScopeId, ScopeKind};

use super::{ArgSource, Assignment, JvmFile, PendingArg};

/// How many assignments, calls and returns a path may go through.
const MAX_DEPTH: usize = 6;
/// How many values an argument may have before it is considered unknown.
const MAX_CANDIDATES: usize = 16;

/// What a resolution is in the middle of, to stop at cycles and depth.
type Trail = Vec<(ScopeId, String)>;

impl JvmFile {
    /// The values `arg` may hold, as an [`ArgValue::OneOf`], or `None` when
    /// none is known.
    pub(super) fn flow_value(&self, arg: &PendingArg, scope: ScopeId) -> Option<ArgValue> {
        let candidates = self.candidates(arg, scope, &mut Vec::new());
        (!candidates.is_empty()).then_some(ArgValue::OneOf(candidates))
    }

    fn candidates(&self, arg: &PendingArg, scope: ScopeId, trail: &mut Trail) -> Vec<Candidate> {
        if trail.len() >= MAX_DEPTH {
            return Vec::new();
        }
        let found = match &arg.source {
            ArgSource::Value(ArgValue::Unknown) => Vec::new(),
            ArgSource::Value(value) => vec![Candidate {
                value: value.clone(),
                flow: vec![step(arg.location, format!("{} is written here", arg.raw))],
            }],
            ArgSource::Name(name) => self.variable(scope, name, false, arg.location, trail),
            ArgSource::Member { owner, name } if owner == "this" => {
                self.variable(scope, name, true, arg.location, trail)
            }
            ArgSource::Member { owner, name } => self
                .member_constant(scope, owner, name)
                .map(|value| {
                    vec![Candidate {
                        value,
                        flow: vec![step(arg.location, format!("{owner}.{name} is a constant"))],
                    }]
                })
                .unwrap_or_default(),
            ArgSource::Concat(parts) => self.concat(parts, scope, trail),
            ArgSource::Choice(options) => options
                .iter()
                .flat_map(|option| self.candidates(option, scope, trail))
                .collect(),
            ArgSource::Call { method, args } => self.returns(method, args.len(), trail),
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

    /// A local variable, parameter or field (`this.name` when `field`),
    /// referred to at `at`.
    fn variable(
        &self,
        scope: ScopeId,
        name: &str,
        field: bool,
        at: Location,
        trail: &mut Trail,
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
        if trail.contains(&key) {
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
        trail.push(key);
        let mut found = Vec::new();
        for assignment in self.assignments.iter().filter(|a| a.name == name) {
            if self.assignment_target(assignment) != Some(declared) {
                continue;
            }
            for mut candidate in self.candidates(&assignment.value, assignment.scope, trail) {
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
            found.extend(self.passed_to(declared, name, index, trail));
        }
        trail.pop();
        found
    }

    /// The values the calls in this file pass as parameter `index` of
    /// `method`, provided no overload makes the call ambiguous.
    fn passed_to(
        &self,
        method: ScopeId,
        param: &str,
        index: usize,
        trail: &mut Trail,
    ) -> Vec<Candidate> {
        let Some(name) = self.unit.scope(method).name.as_deref() else {
            return Vec::new();
        };
        let arity = self.arity(method);
        if self.method_scope(name, arity) != Some(method) {
            return Vec::new();
        }
        let mut found = Vec::new();
        for call in &self.local_calls {
            if call.method != name || call.args.len() != arity {
                continue;
            }
            let arg = &call.args[index];
            for mut candidate in self.candidates(arg, call.scope, trail) {
                candidate.flow.push(step(
                    arg.location,
                    format!("passed as {param} to {name}(...)"),
                ));
                found.push(candidate);
            }
        }
        found
    }

    /// The values returned by the method of this file named `name` that
    /// takes `arity` arguments, when exactly one does.
    fn returns(&self, name: &str, arity: usize, trail: &mut Trail) -> Vec<Candidate> {
        let Some(method) = self.method_scope(name, arity) else {
            return Vec::new();
        };
        let key = (method, "<return>".to_owned());
        if trail.contains(&key) {
            return Vec::new();
        }
        trail.push(key);
        let mut found = Vec::new();
        for (scope, value) in self.returns.iter().filter(|(scope, _)| *scope == method) {
            for mut candidate in self.candidates(value, *scope, trail) {
                candidate
                    .flow
                    .push(step(value.location, format!("returned by {name}(...)")));
                found.push(candidate);
            }
        }
        trail.pop();
        found
    }

    /// Every combination of the parts' values, as long as one part at least
    /// is a string (`KEY_BITS + 1` is not a concatenation).
    fn concat(&self, parts: &[PendingArg], scope: ScopeId, trail: &mut Trail) -> Vec<Candidate> {
        let mut combinations = vec![(String::new(), Vec::new())];
        let mut has_string = false;
        for part in parts {
            let candidates = self.candidates(part, scope, trail);
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

    /// The only method of this file with that name and arity.
    fn method_scope(&self, name: &str, arity: usize) -> Option<ScopeId> {
        let mut matching = self
            .unit
            .scopes()
            .iter()
            .enumerate()
            .filter_map(|(index, scope)| {
                let id = ScopeId(u32::try_from(index).ok()?);
                (scope.kind == ScopeKind::Method
                    && scope.name.as_deref() == Some(name)
                    && self.arity(id) == arity)
                    .then_some(id)
            });
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    fn arity(&self, method: ScopeId) -> usize {
        self.params.get(&method).map_or(0, Vec::len)
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

fn step(location: Location, note: String) -> FlowStep {
    FlowStep { location, note }
}
