//! Compiled dependencies as a type oracle: a class file becomes the
//! [`Library`] declarations `link` uses to follow calls into libraries (the
//! type `jsch.getSession(...)` returns, the interfaces a library class
//! implements). Signatures only; method bodies are never read.

use shorwatch_core::ir::{Library, MethodSummary, TypeDecl, TypeRef};

use crate::LangError;
use classfile::{ACC_BRIDGE, ACC_MODULE, ACC_PROTECTED, ACC_PUBLIC, ACC_SYNTHETIC};

mod classfile;
#[cfg(test)]
mod tests;

/// The declarations of one class file. Synthetic, anonymous and local
/// classes, `module-info` and `package-info` declare nothing a project can
/// call, and give an empty [`Library`].
pub fn read_class(bytes: &[u8]) -> Result<Library, LangError> {
    let class = classfile::parse(bytes).map_err(LangError::Class)?;
    let mut library = Library::default();
    if class.access & (ACC_SYNTHETIC | ACC_MODULE) != 0
        || class.name.ends_with("package-info")
        || is_anonymous(&class.name)
    {
        return Ok(library);
    }
    let name = type_name(&class.name);
    let supertypes = class
        .super_name
        .iter()
        .chain(&class.interfaces)
        .map(|s| type_name(s))
        .filter(|s| s != "java.lang.Object")
        .map(TypeRef::qualified)
        .collect();
    // Kotlin compiles `companion object` members into `X$Companion`; the
    // sources call them on `X`, as the Kotlin frontend records them.
    let owner = name.strip_suffix(".Companion").unwrap_or(&name).to_owned();
    for method in &class.methods {
        if method.access & (ACC_PUBLIC | ACC_PROTECTED) == 0
            || method.access & (ACC_BRIDGE | ACC_SYNTHETIC) != 0
            || method.name.starts_with('<')
        {
            continue;
        }
        let Some((arity, Some(ret))) = classfile::signature(&method.descriptor) else {
            continue;
        };
        let ret = type_name(ret);
        if matches!(ret.as_str(), "java.lang.Object" | "java.lang.String") {
            continue;
        }
        library.methods.push(MethodSummary {
            owner: owner.clone(),
            name: method.name.clone().into_owned(),
            arity,
            return_type: Some(TypeRef::qualified(ret)),
            returns: Vec::new(),
        });
    }
    library.types.push(TypeDecl { name, supertypes });
    Ok(library)
}

/// `java/util/Map$Entry` -> `java.util.Map.Entry`, the way sources name it.
fn type_name(internal: &str) -> String {
    internal.replace(['/', '$'], ".")
}

/// `Outer$1`, `Outer$1Local`: classes the sources cannot name.
fn is_anonymous(internal: &str) -> bool {
    internal
        .rsplit('/')
        .next()
        .unwrap_or(internal)
        .split('$')
        .skip(1)
        .any(|part| part.starts_with(|c: char| c.is_ascii_digit()))
}
