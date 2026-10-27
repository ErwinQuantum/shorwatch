//! What compiled dependencies declare, read from their class files: the
//! types the sources cannot see (a library's `Session`, a JDK interface)
//! and the declared return types of their methods.

use super::{MethodSummary, TypeDecl};

/// Declarations of the libraries a project is compiled against. Signatures
/// only: method bodies are never read, so values never come from a library,
/// only the types that let [`crate::link`] follow calls through it.
#[derive(Debug, Default, Clone)]
pub struct Library {
    pub types: Vec<TypeDecl>,
    /// Methods with a declared return type of their own (`returns` empty).
    pub methods: Vec<MethodSummary>,
}

impl Library {
    pub fn is_empty(&self) -> bool {
        self.types.is_empty() && self.methods.is_empty()
    }

    pub fn extend(&mut self, other: Library) {
        self.types.extend(other.types);
        self.methods.extend(other.methods);
    }
}
