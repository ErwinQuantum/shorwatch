//! Small predicates and helpers over C# syntax.

use tree_sitter::Node;

/// Whether the declaration `node` (or the statement around it) carries the
/// modifier, such as `const` or `readonly`.
pub(super) fn has_modifier(node: Node<'_>, src: &str, modifier: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|c| c.kind() == "modifier")
        .any(|m| &src[m.byte_range()] == modifier)
}

/// `a`, `this.x`, `A.B.C`: nothing but names, so nothing inside to analyze.
pub(super) fn is_name_path(node: Node<'_>) -> bool {
    match node.kind() {
        "identifier" | "this_expression" | "qualified_name" | "generic_name" => true,
        "member_access_expression" => node
            .child_by_field_name("expression")
            .is_some_and(is_name_path),
        _ => false,
    }
}

/// `global::System.Security.Cryptography.RSA?` -> `System.Security.Cryptography.RSA`.
/// Generics, arrays and nullability are dropped.
pub(super) fn type_name(written: &str) -> String {
    let written = written.trim();
    let written = written.strip_prefix("global::").unwrap_or(written);
    let base = written.split(['<', '[', '?']).next().unwrap_or(written);
    base.split_whitespace().collect()
}

/// The name a `name` field holds: a plain identifier, or the identifier of a
/// generic name (`BarAsync<int>`).
pub(super) fn simple_name<'s>(node: Node<'_>, src: &'s str) -> Option<&'s str> {
    match node.kind() {
        "identifier" => Some(&src[node.byte_range()]),
        "generic_name" => {
            let mut cursor = node.walk();
            let name = node
                .named_children(&mut cursor)
                .find(|c| c.kind() == "identifier")?;
            Some(&src[name.byte_range()])
        }
        _ => None,
    }
}

/// The expression an `argument` wraps, past a `name:` label.
pub(super) fn argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = argument.walk();
    argument
        .named_children(&mut cursor)
        .filter(|c| c.kind() != "name_colon")
        .last()
}

/// The method an `invocation_expression` calls, and the expression it is
/// called on: `rsa.SignData(..)`, `Foo.Bar<T>(..)`, `_r?.Export(..)`.
pub(super) fn invoked<'t, 's>(call: Node<'t>, src: &'s str) -> Option<(Option<Node<'t>>, &'s str)> {
    let function = call.child_by_field_name("function")?;
    match function.kind() {
        "member_access_expression" => Some((
            function.child_by_field_name("expression"),
            simple_name(function.child_by_field_name("name")?, src)?,
        )),
        "conditional_access_expression" => {
            let binding = {
                let mut cursor = function.walk();
                function
                    .named_children(&mut cursor)
                    .find(|c| c.kind() == "member_binding_expression")?
            };
            Some((
                function.child_by_field_name("condition"),
                simple_name(binding.child_by_field_name("name")?, src)?,
            ))
        }
        "identifier" | "generic_name" => Some((None, simple_name(function, src)?)),
        _ => None,
    }
}

/// The methods of the calls `literal` is an argument of, innermost first,
/// up to the enclosing block or lambda.
pub(super) fn enclosing_calls(literal: Node<'_>, src: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut child = literal;
    for _ in 0..crate::depth::MAX_ENCLOSING {
        let Some(parent) = child.parent() else { break };
        match parent.kind() {
            "invocation_expression" if parent.child_by_field_name("arguments") == Some(child) => {
                if let Some((_, name)) = invoked(parent, src) {
                    calls.push(name.to_owned());
                }
            }
            // `new Rfc2898DeriveBytes(pw, salt, n, HashAlgorithmName.SHA1)`: the
            // type being constructed is what receives the argument.
            "object_creation_expression"
                if parent.child_by_field_name("arguments") == Some(child) =>
            {
                if let Some(ty) = parent.child_by_field_name("type") {
                    let written = &src[ty.byte_range()];
                    calls.push(
                        type_name(written)
                            .rsplit('.')
                            .next()
                            .unwrap_or(written)
                            .to_owned(),
                    );
                }
            }
            "block" | "declaration_list" | "lambda_expression" | "compilation_unit" => break,
            _ => {}
        }
        child = parent;
    }
    calls
}

/// `T` of `IOptions<T>`, `IOptionsSnapshot<T>` and `IOptionsMonitor<T>`: the
/// options type a variable declared with one of them reads through `.Value`.
pub(super) fn options_inner(written: &str) -> Option<String> {
    let (head, rest) = written.trim().split_once('<')?;
    let name = head.trim().rsplit('.').next()?;
    if !matches!(name, "IOptions" | "IOptionsSnapshot" | "IOptionsMonitor") {
        return None;
    }
    let inner = rest.trim_end_matches('?').strip_suffix('>')?;
    (!inner.contains(['<', ','])).then(|| type_name(inner))
}

/// The type arguments of the method a call names: `Configure<JwtOptions>(..)`
/// (`function` is the call's `function` field).
pub(super) fn generic_args<'s>(function: Node<'_>, src: &'s str) -> Vec<&'s str> {
    let name = if function.kind() == "member_access_expression" {
        function.child_by_field_name("name")
    } else {
        Some(function)
    };
    let Some(name) = name.filter(|n| n.kind() == "generic_name") else {
        return Vec::new();
    };
    let mut cursor = name.walk();
    let Some(list) = name
        .named_children(&mut cursor)
        .find(|c| c.kind() == "type_argument_list")
    else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .map(|ty| &src[ty.byte_range()])
        .collect()
}
