//! One analyzed file: its lexical scopes and the facts found in them.

use serde::{Deserialize, Serialize};

use super::{ConstantDecl, Fact, FactKind, Language, Location, MethodSummary, TypeDecl};

/// Lexical nesting level. Ordered from widest to narrowest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    File,
    /// A class, interface, enum or record (or the language's equivalent).
    Type,
    /// A method, constructor or initializer block.
    Method,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ScopeId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Scope {
    pub kind: ScopeKind,
    pub name: Option<String>,
    pub parent: Option<ScopeId>,
}

/// What a file is for. Findings in test code are still real, but rarely what
/// a migration starts with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeRole {
    #[default]
    Production,
    Test,
}

impl CodeRole {
    fn is_production(&self) -> bool {
        *self == CodeRole::Production
    }
}

/// One analyzed file. `path` is an opaque identifier (a relative path, a URI…);
/// the core never touches the file system, so whoever knows the project's
/// layout sets the [`CodeRole`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceUnit {
    path: String,
    language: Language,
    #[serde(skip_serializing_if = "CodeRole::is_production")]
    role: CodeRole,
    scopes: Vec<Scope>,
    pub(crate) facts: Vec<Fact>,
    /// What this file's methods return, for data flow across files.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    methods: Vec<MethodSummary>,
    /// The types this file declares, with their supertypes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    types: Vec<TypeDecl>,
    /// The constants its types declare.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    constants: Vec<ConstantDecl>,
}

impl SourceUnit {
    pub fn new(path: impl Into<String>, language: Language) -> Self {
        Self {
            path: path.into(),
            language,
            role: CodeRole::Production,
            scopes: vec![Scope {
                kind: ScopeKind::File,
                name: None,
                parent: None,
            }],
            facts: Vec::new(),
            methods: Vec::new(),
            types: Vec::new(),
            constants: Vec::new(),
        }
    }

    pub const ROOT: ScopeId = ScopeId(0);

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn language(&self) -> Language {
        self.language
    }

    pub fn role(&self) -> CodeRole {
        self.role
    }

    pub fn set_role(&mut self, role: CodeRole) {
        self.role = role;
    }

    pub fn methods(&self) -> &[MethodSummary] {
        &self.methods
    }

    pub fn add_method(&mut self, method: MethodSummary) {
        self.methods.push(method);
    }

    pub fn types(&self) -> &[TypeDecl] {
        &self.types
    }

    pub fn add_type(&mut self, decl: TypeDecl) {
        self.types.push(decl);
    }

    pub fn constants(&self) -> &[ConstantDecl] {
        &self.constants
    }

    pub fn add_constant(&mut self, constant: ConstantDecl) {
        self.constants.push(constant);
    }

    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// # Panics
    /// If `id` does not belong to this unit.
    pub fn scope(&self, id: ScopeId) -> &Scope {
        &self.scopes[id.0 as usize]
    }

    /// # Panics
    /// If `parent` does not belong to this unit.
    pub fn add_scope(&mut self, kind: ScopeKind, name: Option<String>, parent: ScopeId) -> ScopeId {
        assert!(
            (parent.0 as usize) < self.scopes.len(),
            "unknown parent scope"
        );
        let id = ScopeId(u32::try_from(self.scopes.len()).expect("too many scopes"));
        self.scopes.push(Scope {
            kind,
            name,
            parent: Some(parent),
        });
        id
    }

    pub fn push(&mut self, kind: FactKind, scope: ScopeId, location: Location) {
        self.facts.push(Fact {
            kind,
            scope,
            location,
        });
    }

    /// Walks up from `id` to the nearest scope of `kind` or wider. Falls back
    /// to the file scope.
    pub fn enclosing(&self, id: ScopeId, kind: ScopeKind) -> ScopeId {
        let mut current = id;
        loop {
            let scope = self.scope(current);
            if scope.kind <= kind {
                return current;
            }
            match scope.parent {
                Some(parent) => current = parent,
                None => return current,
            }
        }
    }

    /// Whether `inner` is `outer` or nested inside it.
    pub fn is_within(&self, inner: ScopeId, outer: ScopeId) -> bool {
        let mut current = Some(inner);
        while let Some(id) = current {
            if id == outer {
                return true;
            }
            current = self.scope(id).parent;
        }
        false
    }
}
