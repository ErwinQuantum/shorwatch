//! Small predicates and helpers over Java syntax.

use tree_sitter::Node;

pub(super) fn has_modifier(node: Node<'_>, modifier: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|c| c.kind() == "modifiers")
        .any(|modifiers| {
            let mut inner = modifiers.walk();
            modifiers.children(&mut inner).any(|m| m.kind() == modifier)
        })
}

/// `a`, `this.x`, `a.b.C`: nothing but names, so nothing inside to analyze.
pub(super) fn is_name_path(node: Node<'_>) -> bool {
    match node.kind() {
        "identifier" | "this" | "super" => true,
        "field_access" => node.child_by_field_name("object").is_some_and(is_name_path),
        _ => false,
    }
}

/// Whether `node` is the name slot of its parent (a declaration, an invoked
/// method, a selected field) rather than an expression with a value.
pub(super) fn is_name_slot(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        ["name", "field"]
            .iter()
            .any(|field| parent.child_by_field_name(field) == Some(node))
    })
}

/// `Map<String, Cipher>[]` -> `Map`. Annotations and generics are dropped.
pub(super) fn type_name(written: &str) -> String {
    let base = written.split(['<', '[']).next().unwrap_or(written);
    base.split_whitespace().last().unwrap_or(base).to_owned()
}

/// The methods of the calls `literal` is an argument of, innermost first,
/// up to the enclosing statement block or lambda.
pub(super) fn enclosing_calls(literal: Node<'_>, src: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut child = literal;
    while let Some(parent) = child.parent() {
        match parent.kind() {
            "method_invocation" if parent.child_by_field_name("arguments") == Some(child) => {
                if let Some(name) = parent.child_by_field_name("name") {
                    calls.push(src[name.byte_range()].to_owned());
                }
            }
            "block" | "class_body" | "lambda_expression" | "program" => break,
            _ => {}
        }
        child = parent;
    }
    calls
}
