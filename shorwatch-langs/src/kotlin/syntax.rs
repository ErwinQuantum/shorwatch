//! Small predicates and helpers over Kotlin syntax.

use tree_sitter::Node;

use crate::jvm::starts_uppercase;

/// `Cipher`, `ECGenParameterSpec`: a name that reads as a class. Kotlin has
/// no `new`, so `Name(...)` is a constructor call when `Name` looks like a
/// type. Upper-case names without lower-case letters (`RSA256`) are taken as
/// functions or constants, as JVM naming conventions have them.
pub(super) fn looks_like_type(name: &str) -> bool {
    starts_uppercase(name) && name.chars().any(char::is_lowercase)
}

/// `a`, `this`, `this.x`, `a.b.C`: nothing but names, so nothing inside to
/// analyze.
pub(super) fn is_name_path(node: Node<'_>) -> bool {
    match node.kind() {
        "identifier" | "this_expression" => true,
        "navigation_expression" => {
            navigation_parts(node).is_some_and(|(object, _)| is_name_path(object))
        }
        _ => false,
    }
}

/// `a.b.C` as written, without whitespace, safe-call marks or comments.
pub(super) fn name_path(node: Node<'_>, src: &str) -> String {
    match navigation_parts(node) {
        Some((object, member)) => format!("{}.{}", name_path(object, src), text(member, src)),
        None if node.kind() == "this_expression" => "this".to_owned(),
        None => text(node, src).to_owned(),
    }
}

/// The object and the member name of `object.member` (or `object?.member`).
pub(super) fn navigation_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "navigation_expression" {
        return None;
    }
    let object = node.named_child(0)?;
    let member = node.named_child(node.named_child_count().checked_sub(1)?)?;
    (object != member && member.kind() == "identifier").then_some((object, member))
}

/// `java.security.Signature?` -> `java.security.Signature`, `List<Cipher>` ->
/// `List`. `None` for function and other non-class types.
pub(super) fn type_name(node: Node<'_>, src: &str) -> Option<String> {
    match node.kind() {
        "user_type" => {
            let mut cursor = node.walk();
            let parts: Vec<_> = node
                .named_children(&mut cursor)
                .filter(|c| c.kind() == "identifier")
                .map(|c| text(c, src))
                .collect();
            (!parts.is_empty()).then(|| parts.join("."))
        }
        "nullable_type" => type_name(node.named_child(0)?, src),
        _ => None,
    }
}

/// The declared type among a declaration's children, if written.
pub(super) fn declared_type(node: Node<'_>, src: &str) -> Option<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|c| matches!(c.kind(), "user_type" | "nullable_type"))
        .and_then(|t| type_name(t, src))
}

/// Whether an identifier is used as a value. It is not when it names
/// something (a declaration, a type, a selected member, an argument label) or
/// is the callee of a call, which the call itself accounts for.
pub(super) fn is_value(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    let first = parent.named_child(0) == Some(identifier);
    let last = parent.named_child(parent.named_child_count().saturating_sub(1)) == Some(identifier);
    match parent.kind() {
        "navigation_expression" => first,
        "call_expression" => !first,
        "value_argument" => last,
        "variable_declaration"
        | "class_parameter"
        | "parameter"
        | "user_type"
        | "import"
        | "qualified_identifier"
        | "package_header"
        | "enum_entry"
        | "type_alias"
        | "label"
        | "class_declaration"
        | "object_declaration"
        | "function_declaration"
        | "type_parameter" => false,
        _ => true,
    }
}

pub(super) fn has_child(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| c.kind() == kind)
}

pub(super) fn child_of_kind<'t>(node: Node<'t>, kind: &str) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|c| c.kind() == kind)
}

pub(super) fn text<'s>(node: Node<'_>, src: &'s str) -> &'s str {
    &src[node.byte_range()]
}

/// The value of an `if` branch or `when` entry body: its last expression.
pub(super) fn branch_value(node: Node<'_>) -> Node<'_> {
    match node.kind() {
        "control_structure_body" | "block" | "statements" => node
            .named_child(node.named_child_count().saturating_sub(1))
            .map_or(node, branch_value),
        _ => node,
    }
}

/// The methods of the calls `literal` is an argument of, innermost first,
/// up to the enclosing block or lambda.
pub(super) fn enclosing_calls(literal: Node<'_>, src: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut child = literal;
    while let Some(parent) = child.parent() {
        match parent.kind() {
            "call_expression" if child.kind() == "value_arguments" => {
                let method = parent
                    .named_child(0)
                    .and_then(|callee| match callee.kind() {
                        "identifier" => Some(callee),
                        "navigation_expression" => {
                            navigation_parts(callee).map(|(_, member)| member)
                        }
                        _ => None,
                    });
                if let Some(method) = method {
                    calls.push(text(method, src).to_owned());
                }
            }
            "block" | "class_body" | "lambda_literal" | "function_body" | "source_file" => break,
            _ => {}
        }
        child = parent;
    }
    calls
}
