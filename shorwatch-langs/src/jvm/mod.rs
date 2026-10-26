//! What the JVM frontends share. Java and Kotlin call the same library APIs,
//! so once a traversal has recorded a file's names, both resolve them alike.
//!
//! A frontend's traversal (phase one) fills a [`JvmFile`]: scopes, imports,
//! declared symbols and *pending* facts whose names are still unresolved.
//! [`JvmFile::resolve`] (phase two, in [`resolve`]) then turns pending facts
//! into the unit's facts, once declarations made after their use are known.
//!
//! - [`model`]: what phase one records;
//! - [`resolve`]: phase two, names to types, constant and injected values.

use std::collections::{HashMap, HashSet};

use shorwatch_core::Language;
use shorwatch_core::ir::{Location, ScopeId, SourceUnit};

pub(crate) use model::{ArgSource, Pending, PendingArg, Receiver, Symbol};

mod model;
mod resolve;

/// One JVM source file between the two phases of its lowering.
#[derive(Debug)]
pub(crate) struct JvmFile {
    pub(crate) unit: SourceUnit,
    /// Simple name (or alias) -> fully qualified name, from type imports.
    pub(crate) imports: HashMap<String, String>,
    /// Member name -> fully qualified owner type, from member imports
    /// (`import static` in Java, any member import in Kotlin).
    pub(crate) static_imports: HashMap<String, String>,
    /// The file's package (empty for the default package).
    pub(crate) package: String,
    /// Packages imported on demand (`import a.b.*`).
    pub(crate) on_demand_imports: Vec<String>,
    /// Whether the file imports a whole module (`import module java.base;`,
    /// Java 25): every package the module exports, which only the module
    /// graph knows, so an unimported name may come from anywhere.
    pub(crate) module_imports: bool,
    /// Methods declared in this file, which shadow imported ones.
    pub(crate) methods: HashSet<String>,
    pub(crate) symbols: HashMap<(ScopeId, String), Symbol>,
    pending: Vec<(Pending, ScopeId, Location)>,
}

impl JvmFile {
    pub(crate) fn new(path: &str, language: Language) -> Self {
        Self {
            unit: SourceUnit::new(path, language),
            imports: HashMap::new(),
            static_imports: HashMap::new(),
            package: String::new(),
            on_demand_imports: Vec::new(),
            module_imports: false,
            methods: HashSet::new(),
            symbols: HashMap::new(),
            pending: Vec::new(),
        }
    }

    pub(crate) fn defer(&mut self, pending: Pending, scope: ScopeId, location: Location) {
        self.pending.push((pending, scope, location));
    }

    /// The symbol `name` refers to from `scope`, searching enclosing scopes.
    pub(crate) fn lookup(&self, mut scope: ScopeId, name: &str) -> Option<&Symbol> {
        loop {
            if let Some(symbol) = self.symbols.get(&(scope, name.to_owned())) {
                return Some(symbol);
            }
            scope = self.unit.scope(scope).parent?;
        }
    }
}

/// JVM naming convention: types start uppercase, members and packages don't.
pub(crate) fn starts_uppercase(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}
