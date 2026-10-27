//! The project's type hierarchy, from the types each file declares and the
//! types they extend or implement, plus the library types they rely on. A call through a type can reach a method
//! of that type, of a subtype that overrides it, or of a supertype it
//! inherits it from: the type's *related* types.

use std::collections::{HashMap, HashSet};

use crate::ir::{SourceUnit, TypeDecl, TypeRef};

#[derive(Debug, Default)]
pub(super) struct Hierarchy {
    /// Declared types by simple name, to resolve references to them.
    by_simple_name: HashMap<String, Vec<String>>,
    /// Every type's supertypes and subtypes, transitively.
    ancestors: HashMap<String, HashSet<String>>,
    descendants: HashMap<String, HashSet<String>>,
}

impl Hierarchy {
    pub(super) fn of(units: &[SourceUnit], library: &[&TypeDecl]) -> Self {
        let decls: Vec<&TypeDecl> = units
            .iter()
            .flat_map(SourceUnit::types)
            .chain(library.iter().copied())
            .collect();
        let mut by_simple_name: HashMap<String, Vec<String>> = HashMap::new();
        for decl in &decls {
            let names = by_simple_name
                .entry(simple(&decl.name).to_owned())
                .or_default();
            if !names.contains(&decl.name) {
                names.push(decl.name.clone());
            }
        }
        let mut hierarchy = Self {
            by_simple_name,
            ..Self::default()
        };
        let mut parents: HashMap<&str, Vec<String>> = HashMap::new();
        for decl in &decls {
            let resolved: Vec<String> = decl
                .supertypes
                .iter()
                .flat_map(|s| hierarchy.declared(s))
                .map(str::to_owned)
                .collect();
            parents.entry(&decl.name).or_default().extend(resolved);
        }
        for name in parents.keys() {
            let mut seen = HashSet::new();
            let mut stack: Vec<&str> = parents[name].iter().map(String::as_str).collect();
            while let Some(parent) = stack.pop() {
                if parent != *name && seen.insert(parent.to_owned()) {
                    stack.extend(
                        parents
                            .get(parent)
                            .into_iter()
                            .flatten()
                            .map(String::as_str),
                    );
                }
            }
            for ancestor in &seen {
                hierarchy
                    .descendants
                    .entry(ancestor.clone())
                    .or_default()
                    .insert((*name).to_owned());
            }
            hierarchy.ancestors.insert((*name).to_owned(), seen);
        }
        hierarchy
    }

    /// The project's types `reference` may denote.
    pub(super) fn declared<'h>(&'h self, reference: &TypeRef) -> Vec<&'h str> {
        self.by_simple_name
            .get(simple(&reference.name))
            .into_iter()
            .flatten()
            .filter(|name| reference.is(name))
            .map(String::as_str)
            .collect()
    }

    /// `ty` and its supertypes, where a constant it uses may be declared.
    pub(super) fn with_ancestors<'h>(&'h self, ty: &'h str) -> impl Iterator<Item = &'h str> {
        let ancestors = self.ancestors.get(ty).into_iter().flatten();
        std::iter::once(ty).chain(ancestors.map(String::as_str))
    }

    /// `ty`, its supertypes and its subtypes: the types whose methods a call
    /// through `ty` may reach, and the types through which a method of `ty`
    /// may be called.
    pub(super) fn related<'h>(&'h self, ty: &'h str) -> impl Iterator<Item = &'h str> {
        let ancestors = self.ancestors.get(ty).into_iter().flatten();
        let descendants = self.descendants.get(ty).into_iter().flatten();
        std::iter::once(ty).chain(ancestors.chain(descendants).map(String::as_str))
    }
}

fn simple(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}
