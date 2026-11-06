//! What the JVM frontends share. Java and Kotlin call the same library APIs,
//! so once a traversal has recorded a file's names, both resolve them alike.
//!
//! A frontend's traversal (phase one) fills a [`JvmFile`]: scopes, imports,
//! declared symbols and *pending* facts whose names are still unresolved.
//! [`JvmFile::resolve`] (phase two, in [`resolve`]) then turns pending facts
//! into the unit's facts, once declarations made after their use are known.
//!
//! - [`model`]: what phase one records;
//! - [`resolve`]: phase two, names to types, constant and injected values;
//! - [`flow`]: phase two, values that reach an argument through variables,
//!   parameters and returns of this file.

use std::collections::{HashMap, HashSet};

use shorwatch_core::Language;
use shorwatch_core::ir::{Location, ScopeId, SourceUnit};

pub(crate) use model::{ArgSource, Assignment, LocalCall, Pending, PendingArg, Receiver, Symbol};

mod flow;
mod model;
mod resolve;

/// Calls in a receiver chain that are kept (`a.b().c().d()` has three):
/// longer builder chains carry no algorithm worth the depth.
pub(crate) const MAX_CHAIN: usize = 8;

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
    /// Assignments and non-constant initializers, for data flow.
    pub(crate) assignments: Vec<Assignment>,
    /// Parameter names of each method scope, in order.
    pub(crate) params: HashMap<ScopeId, Vec<String>>,
    /// `return` values (and Kotlin expression bodies) by method scope.
    pub(crate) returns: Vec<(ScopeId, PendingArg)>,
    /// Declared return types by method scope, as written.
    pub(crate) return_types: HashMap<ScopeId, String>,
    /// Type scopes and the supertypes they name, as written.
    pub(crate) type_decls: Vec<(ScopeId, Vec<String>)>,
    /// The constants of each enum scope, in order: `name()` of an enum value
    /// is one of them.
    pub(crate) enum_constants: HashMap<ScopeId, Vec<(String, Location)>>,
    /// Kotlin's primary-constructor properties (`class K(val jce: String)`)
    /// by type scope: reading `k.jce` is calling an accessor.
    pub(crate) properties: HashMap<ScopeId, Vec<(String, Location)>>,
    /// Types annotated `@ConfigurationProperties(prefix = "...")`: their
    /// fields are bound to `<prefix>.<field>` keys of the configuration.
    pub(crate) config_prefixes: HashMap<ScopeId, String>,
    /// Calls that may target a method of this file, gathered in phase two.
    local_calls: Vec<LocalCall>,
    /// Type scopes by name and method scopes by declaring type, name and
    /// arity, indexed once in phase two: big generated files have thousands.
    type_scopes: HashMap<String, Vec<ScopeId>>,
    method_scopes: HashMap<(Option<ScopeId>, String, usize), Vec<ScopeId>>,
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
            assignments: Vec::new(),
            params: HashMap::new(),
            returns: Vec::new(),
            return_types: HashMap::new(),
            type_decls: Vec::new(),
            enum_constants: HashMap::new(),
            properties: HashMap::new(),
            config_prefixes: HashMap::new(),
            local_calls: Vec::new(),
            type_scopes: HashMap::new(),
            method_scopes: HashMap::new(),
            pending: Vec::new(),
        }
    }

    pub(crate) fn defer(&mut self, pending: Pending, scope: ScopeId, location: Location) {
        self.pending.push((pending, scope, location));
    }

    /// The symbol `name` refers to from `scope`, searching enclosing scopes.
    pub(crate) fn lookup(&self, scope: ScopeId, name: &str) -> Option<&Symbol> {
        let declared = self.lookup_scope(scope, name)?;
        self.symbols.get(&(declared, name.to_owned()))
    }

    /// The scope that declares the `name` visible from `scope`.
    pub(crate) fn lookup_scope(&self, mut scope: ScopeId, name: &str) -> Option<ScopeId> {
        loop {
            if self.symbols.contains_key(&(scope, name.to_owned())) {
                return Some(scope);
            }
            scope = self.unit.scope(scope).parent?;
        }
    }
}

/// JVM naming convention: types start uppercase, members and packages don't.
pub(crate) fn starts_uppercase(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}
