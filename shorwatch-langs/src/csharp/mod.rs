//! C# frontend (tree-sitter-c-sharp).
//!
//! Like Java's, the lowering has two phases: one traversal records scopes,
//! `using`s, declarations and *pending* facts whose names are still unresolved;
//! [`crate::managed`] then resolves them, shared with Java and Kotlin, so data
//! flow (constants, parameters, returns, across files) comes with it.
//!
//! What differs from Java:
//!
//! - `using` imports a *namespace*, never a type (`using System.Security.Cryptography;`),
//!   so a type name can come from any imported namespace;
//! - a property is assigned, not called: `aes.KeySize = 128` is lowered as the
//!   call `aes.set_KeySize(128)` (the accessor's name in the compiled form), so
//!   rules match it like any other call;
//! - `const` and `readonly` are what `final` is, `new()` takes its type from
//!   the declaration, and `a?.B()` is a call on `a`.
//!
//! - this module: the traversal (phase one);
//! - [`literals`]: decoding string and integer literals;
//! - [`syntax`]: small helpers over the tree.

use shorwatch_core::Language;
use shorwatch_core::ir::{ArgValue, FactKind, Location, ScopeId, ScopeKind, SourceUnit};
use tree_sitter::{Node, Parser};

use crate::managed::{
    ArgSource, Assignment, MAX_CHAIN, ManagedFile, Pending, PendingArg, Receiver, Symbol,
    starts_uppercase,
};
use crate::{Frontend, LangError, span};
use literals::{int_value, string_value};
use syntax::{
    argument_value, enclosing_calls, has_modifier, invoked, is_name_path, simple_name, type_name,
};

mod literals;
mod syntax;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, Default)]
pub struct CSharpFrontend;

impl Frontend for CSharpFrontend {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cs"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .map_err(|e| LangError::Grammar(Language::CSharp, e.to_string()))?;
        // tree-sitter recovers from syntax errors, so a partially broken file
        // still yields facts for the parts that parse.
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| LangError::Parse(path.to_owned()))?;
        crate::depth::check(path, tree.root_node())?;
        Ok(Lowering::new(path, source).run(tree.root_node()))
    }
}

struct Lowering<'s> {
    src: &'s str,
    file: ManagedFile,
}

impl<'s> Lowering<'s> {
    fn new(path: &str, src: &'s str) -> Self {
        Self {
            src,
            file: ManagedFile::new(path, Language::CSharp),
        }
    }

    fn run(mut self, root: Node<'_>) -> SourceUnit {
        // Explicit stack: generated code can nest deeper than the call stack likes.
        let mut stack = vec![(root, SourceUnit::ROOT)];
        let mut cursor = root.walk();
        while let Some((node, scope)) = stack.pop() {
            if let Some(child_scope) = self.visit(node, scope) {
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                stack.extend(children.into_iter().rev().map(|c| (c, child_scope)));
            }
        }
        self.file.resolve()
    }

    /// Records what `node` contributes. Returns the scope its children belong
    /// to, or `None` when they need no further visiting.
    fn visit(&mut self, node: Node<'_>, scope: ScopeId) -> Option<ScopeId> {
        match node.kind() {
            "comment" => None,
            "using_directive" => {
                self.using(node, scope);
                None
            }
            "file_scoped_namespace_declaration" => {
                self.namespace(node);
                None
            }
            "namespace_declaration" => {
                self.namespace(node);
                Some(scope)
            }
            "class_declaration"
            | "struct_declaration"
            | "interface_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "enum_declaration" => {
                let name = self.field_text(node, "name").map(str::to_owned);
                let id = self.file.unit.add_scope(ScopeKind::Type, name, scope);
                let supertypes = self.supertypes(node);
                self.file.type_decls.push((id, supertypes));
                Some(id)
            }
            "method_declaration" | "constructor_declaration" | "local_function_statement" => {
                let name = self.field_text(node, "name").map(str::to_owned);
                if let Some(name) = &name {
                    self.file.methods.insert(name.clone());
                }
                let id = self.file.unit.add_scope(ScopeKind::Method, name, scope);
                if let Some(ty) = node
                    .child_by_field_name("returns")
                    .or_else(|| node.child_by_field_name("type"))
                {
                    self.file.return_types.insert(id, type_name(self.text(ty)));
                }
                Some(id)
            }
            "arrow_expression_clause" => {
                // `int M() => expr;`: the expression is what the method returns.
                let of_method = node.parent().is_some_and(|p| {
                    matches!(p.kind(), "method_declaration" | "local_function_statement")
                });
                if let (true, Some(value)) = (of_method, node.named_child(0)) {
                    let value = self.pending(value);
                    self.file.returns.push((scope, value));
                }
                Some(scope)
            }
            "property_declaration" => {
                self.property(node, scope);
                Some(scope)
            }
            "variable_declaration" => {
                self.declare(node, scope);
                Some(scope)
            }
            "parameter" => {
                self.parameter(node, scope);
                None
            }
            "assignment_expression" => {
                self.assign(node, scope);
                Some(scope)
            }
            "return_statement" => {
                if let Some(value) = node.named_child(0) {
                    let value = self.pending(value);
                    self.file.returns.push((scope, value));
                }
                Some(scope)
            }
            "invocation_expression" => {
                self.call(node, scope);
                Some(scope)
            }
            "object_creation_expression" => {
                self.construct(node, scope);
                Some(scope)
            }
            "member_access_expression" => self.member_access(node, scope),
            "string_literal" | "verbatim_string_literal" | "raw_string_literal" => {
                if let Some(value) = string_value(self.text(node)) {
                    let calls = enclosing_calls(node, self.src);
                    self.ready(FactKind::Literal { value, calls }, scope, node);
                }
                None
            }
            _ => Some(scope),
        }
    }

    /// `using A.B;`, `using R = A.B.C;`, `using static A.B.C;` (and `global`
    /// forms). Only the first two bring names in: a static using would need
    /// the members of the type, which a source file cannot say.
    fn using(&mut self, node: Node<'_>, scope: ScopeId) {
        let mut cursor = node.walk();
        let is_static = node.children(&mut cursor).any(|c| c.kind() == "static");
        let alias = self.field_text(node, "name").map(str::to_owned);
        let mut cursor = node.walk();
        let Some(target) = node
            .named_children(&mut cursor)
            .filter(|c| node.child_by_field_name("name") != Some(*c))
            .last()
        else {
            return;
        };
        let target = type_name(self.text(target));
        match alias {
            Some(alias) => {
                self.file.imports.insert(alias, target.clone());
            }
            None if !is_static => self.file.on_demand_imports.push(target.clone()),
            None => {}
        }
        self.ready(FactKind::Import { path: target }, scope, node);
    }

    /// The file's namespace: file-scoped (`namespace A.B;`) or the first block
    /// one. Types of a second block namespace in the same file would be
    /// qualified wrongly; real files hold one.
    fn namespace(&mut self, node: Node<'_>) {
        if self.file.package.is_empty()
            && let Some(name) = self.field_text(node, "name")
        {
            self.file.package = name.split_whitespace().collect();
        }
    }

    /// The types a declaration extends or implements, as written.
    fn supertypes(&self, declaration: Node<'_>) -> Vec<String> {
        let mut cursor = declaration.walk();
        let Some(list) = declaration
            .named_children(&mut cursor)
            .find(|c| c.kind() == "base_list")
        else {
            return Vec::new();
        };
        let mut cursor = list.walk();
        list.named_children(&mut cursor)
            .filter(|c| {
                matches!(
                    c.kind(),
                    "identifier" | "qualified_name" | "generic_name" | "alias_qualified_name"
                )
            })
            .map(|ty| type_name(self.text(ty)))
            .collect()
    }

    /// A field or local declaration: `RSA r = ...`, `var h = SHA1.Create()`,
    /// `const string A = "RSA"`, `ECDsa e = new();`.
    fn declare(&mut self, node: Node<'_>, scope: ScopeId) {
        let is_final = node.parent().is_some_and(|statement| {
            has_modifier(statement, self.src, "const")
                || has_modifier(statement, self.src, "readonly")
        });
        let declared = node
            .child_by_field_name("type")
            .map(|t| type_name(self.text(t)));
        let mut cursor = node.walk();
        let declarators: Vec<_> = node
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "variable_declarator")
            .collect();
        for declarator in declarators {
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name = self.text(name_node);
            let value = declarator
                .named_child(declarator.named_child_count().saturating_sub(1))
                .filter(|v| *v != name_node);
            let ty = match declared.as_deref() {
                Some("var") => value.and_then(|v| self.infer_type(v)),
                other => other.map(str::to_owned),
            };
            let constant = if is_final {
                value.and_then(|v| self.literal(v))
            } else {
                None
            };
            let origin = value.and_then(|v| self.origin(v));
            let call = match (declared.as_deref(), value) {
                (Some("var"), Some(v)) if v.kind() == "invocation_expression" => {
                    self.receiver(v, 0)
                }
                _ => None,
            };
            // `ECDsa e = new();`: the construction takes the declared type.
            if let (Some(value), Some(ty)) = (value, declared.as_deref())
                && value.kind() == "implicit_object_creation_expression"
                && ty != "var"
            {
                let args = self.args(value);
                self.defer(
                    Pending::Construct {
                        ty: ty.to_owned(),
                        args,
                    },
                    scope,
                    value,
                );
            }
            if let (None, Some(value)) = (&constant, value) {
                self.file.assignments.push(Assignment {
                    scope,
                    name: name.to_owned(),
                    field: false,
                    value: self.pending(value),
                    location: self.location(declarator),
                });
            }
            self.file.symbols.insert(
                (scope, name.to_owned()),
                Symbol {
                    ty,
                    constant,
                    origin,
                    call,
                },
            );
        }
    }

    /// `public string Alg { get; set; } = "RSA";` or `public int Bits => 2048;`.
    /// A property nothing can set (no `set`/`init`) holds its literal like a
    /// constant; otherwise the initializer is one more assignment.
    fn property(&mut self, node: Node<'_>, scope: ScopeId) {
        let (Some(ty), Some(name)) = (
            node.child_by_field_name("type"),
            self.field_text(node, "name"),
        ) else {
            return;
        };
        let value = node.child_by_field_name("value");
        let value = value
            .filter(|v| v.kind() == "arrow_expression_clause")
            .and_then(|v| v.named_child(0))
            .or(value);
        let settable = node.child_by_field_name("accessors").is_some_and(|list| {
            let mut cursor = list.walk();
            list.named_children(&mut cursor).any(|accessor| {
                let text = self.text(accessor);
                text.starts_with("set") || text.starts_with("init")
            })
        });
        let constant = match (value, settable) {
            (Some(v), false) => self.literal(v),
            _ => None,
        };
        if let (None, Some(value)) = (&constant, value) {
            self.file.assignments.push(Assignment {
                scope,
                name: name.to_owned(),
                field: false,
                value: self.pending(value),
                location: self.location(node),
            });
        }
        self.file.symbols.insert(
            (scope, name.to_owned()),
            Symbol {
                ty: Some(type_name(self.text(ty))),
                constant,
                ..Symbol::default()
            },
        );
    }

    fn parameter(&mut self, node: Node<'_>, scope: ScopeId) {
        let (Some(ty), Some(name)) = (
            node.child_by_field_name("type"),
            self.field_text(node, "name"),
        ) else {
            return;
        };
        let owner = node.parent().and_then(|list| list.parent());
        let of_method = owner.is_some_and(|d| {
            matches!(
                d.kind(),
                "method_declaration" | "constructor_declaration" | "local_function_statement"
            )
        });
        // A record's components are its constructor's parameters and are
        // read through the properties they declare.
        let of_record = owner.is_some_and(|d| {
            matches!(d.kind(), "record_declaration" | "record_struct_declaration")
        });
        if of_method || of_record {
            self.file
                .params
                .entry(scope)
                .or_default()
                .push(name.to_owned());
        }
        if of_record {
            let location = self.location(node);
            self.file
                .properties
                .entry(scope)
                .or_default()
                .push((name.to_owned(), location));
        }
        self.file.symbols.insert(
            (scope, name.to_owned()),
            Symbol {
                ty: Some(type_name(self.text(ty))),
                ..Symbol::default()
            },
        );
    }

    /// Type of a `var` initializer, when it is obvious from the syntax.
    fn infer_type(&self, value: Node<'_>) -> Option<String> {
        match value.kind() {
            "object_creation_expression" => value
                .child_by_field_name("type")
                .map(|t| type_name(self.text(t))),
            "cast_expression" => value
                .child_by_field_name("type")
                .map(|t| type_name(self.text(t))),
            "as_expression" => value
                .child_by_field_name("right")
                .map(|t| type_name(self.text(t))),
            // `RSA.Create()`: the BCL's factories return their own type.
            "invocation_expression" => {
                let (object, _) = invoked(value, self.src)?;
                let object = object?;
                let text = self.text(object);
                (object.kind() == "identifier" && starts_uppercase(text)).then(|| text.to_owned())
            }
            _ => None,
        }
    }

    /// Arguments of a `Type.Factory(...)` initializer, the same calls that
    /// [`Self::infer_type`] takes the type from.
    fn origin(&self, value: Node<'_>) -> Option<Vec<PendingArg>> {
        if value.kind() != "invocation_expression" {
            return None;
        }
        let (object, _) = invoked(value, self.src)?;
        let object = object?;
        (object.kind() == "identifier" && starts_uppercase(self.text(object)))
            .then(|| self.args(value))
    }

    /// A call's receiver as written. A call as receiver
    /// (`Crypto.Provider().M()`, also longer chains) is typed from its
    /// declared return type later.
    fn receiver(&self, object: Node<'_>, depth: usize) -> Option<Receiver> {
        match object.kind() {
            "identifier" | "generic_name" => {
                simple_name(object, self.src).map(|n| Receiver::Name(n.to_owned()))
            }
            "member_access_expression" | "qualified_name" => Some(Receiver::Path(
                self.text(object).split_whitespace().collect(),
            )),
            "invocation_expression" if depth < MAX_CHAIN => {
                let (owner, method) = invoked(object, self.src)?;
                Some(Receiver::Call {
                    owner: match owner {
                        None => None,
                        Some(o) if self.is_this(o) => None,
                        Some(o) => Some(Box::new(self.receiver(o, depth + 1)?)),
                    },
                    method: method.to_owned(),
                    arity: self.args(object).len(),
                })
            }
            _ => None,
        }
    }

    fn is_this(&self, node: Node<'_>) -> bool {
        self.text(node) == "this"
    }

    fn call(&mut self, node: Node<'_>, scope: ScopeId) {
        let Some((object, method)) = invoked(node, self.src) else {
            return;
        };
        let receiver = object
            .filter(|o| !self.is_this(*o))
            .and_then(|o| self.receiver(o, 0));
        let args = self.args(node);
        let chain = self.chain_after(node);
        self.defer(
            Pending::Call {
                receiver,
                method: method.to_owned(),
                args,
                chain,
            },
            scope,
            node,
        );
    }

    /// The methods called on `node`'s result in the same chain, nearest first.
    fn chain_after(&self, node: Node<'_>) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = node;
        while chain.len() < MAX_CHAIN
            && let Some(access) = current.parent()
            && access.kind() == "member_access_expression"
            && access.child_by_field_name("expression") == Some(current)
            && let Some(call) = access.parent()
            && call.kind() == "invocation_expression"
            && call.child_by_field_name("function") == Some(access)
            && let Some(name) = access
                .child_by_field_name("name")
                .and_then(|n| simple_name(n, self.src))
        {
            chain.push(name.to_owned());
            current = call;
        }
        chain
    }

    fn construct(&mut self, node: Node<'_>, scope: ScopeId) {
        let Some(ty) = node
            .child_by_field_name("type")
            .map(|t| type_name(self.text(t)))
        else {
            return;
        };
        let args = self.args(node);
        self.defer(Pending::Construct { ty, args }, scope, node);
    }

    /// `Owner.NAME`. The method of an invocation (`Owner.Create()`) is not a
    /// field, and a pure name path (`A.B.C.NAME`) has nothing else inside to
    /// visit; anything else (`Call().X`) keeps being traversed.
    fn member_access(&mut self, node: Node<'_>, scope: ScopeId) -> Option<ScopeId> {
        let invoked_here = node.parent().is_some_and(|p| {
            p.kind() == "invocation_expression" && p.child_by_field_name("function") == Some(node)
        });
        if invoked_here {
            return Some(scope);
        }
        let (object, name) = (
            node.child_by_field_name("expression")?,
            node.child_by_field_name("name")
                .and_then(|n| simple_name(n, self.src))?,
        );
        if !is_name_path(object) {
            return Some(scope);
        }
        let owner: String = self.text(object).split_whitespace().collect();
        let calls = enclosing_calls(node, self.src);
        self.defer(
            Pending::Field {
                owner,
                name: name.to_owned(),
                calls,
            },
            scope,
            node,
        );
        None
    }

    /// `name = value` or `this.name = value`, for data flow; and `x.Prop =
    /// value`, which sets a property: the call `x.set_Prop(value)`.
    fn assign(&mut self, node: Node<'_>, scope: ScopeId) {
        let is_plain = node
            .child_by_field_name("operator")
            .is_some_and(|op| self.text(op) == "=");
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        if !is_plain {
            return;
        }
        match left.kind() {
            "identifier" => self.record_assignment(scope, self.text(left), false, right, node),
            "member_access_expression" => {
                let (Some(object), Some(name)) = (
                    left.child_by_field_name("expression"),
                    left.child_by_field_name("name")
                        .and_then(|n| simple_name(n, self.src)),
                ) else {
                    return;
                };
                if self.is_this(object) {
                    self.record_assignment(scope, name, true, right, node);
                } else if let Some(receiver) = self.receiver(object, 0) {
                    let args = vec![self.pending(right)];
                    self.defer(
                        Pending::Call {
                            receiver: Some(receiver),
                            method: format!("set_{name}"),
                            args,
                            chain: Vec::new(),
                        },
                        scope,
                        node,
                    );
                }
            }
            _ => {}
        }
    }

    fn record_assignment(
        &mut self,
        scope: ScopeId,
        name: &str,
        field: bool,
        value: Node<'_>,
        node: Node<'_>,
    ) {
        let value = self.pending(value);
        let location = self.location(node);
        self.file.assignments.push(Assignment {
            scope,
            name: name.to_owned(),
            field,
            value,
            location,
        });
    }

    fn args(&self, node: Node<'_>) -> Vec<PendingArg> {
        let list = node.child_by_field_name("arguments").or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|c| c.kind() == "argument_list")
        });
        let Some(list) = list else {
            return Vec::new();
        };
        let mut cursor = list.walk();
        list.named_children(&mut cursor)
            .filter(|arg| arg.kind() == "argument")
            .filter_map(argument_value)
            .map(|arg| self.pending(arg))
            .collect()
    }

    fn pending(&self, node: Node<'_>) -> PendingArg {
        PendingArg {
            source: self.source(node),
            raw: self.text(node).to_owned(),
            location: self.location(node),
        }
    }

    /// What an expression's value depends on, for phase two to resolve.
    fn source(&self, node: Node<'_>) -> ArgSource {
        if let Some(value) = self.literal(node) {
            return ArgSource::Value(value);
        }
        let unknown = ArgSource::Value(ArgValue::Unknown);
        let mut cursor = node.walk();
        match node.kind() {
            "identifier" => ArgSource::Name(self.text(node).to_owned()),
            "member_access_expression" => match (
                node.child_by_field_name("expression"),
                node.child_by_field_name("name")
                    .and_then(|n| simple_name(n, self.src)),
            ) {
                (Some(owner), Some(name)) if is_name_path(owner) => ArgSource::Member {
                    owner: self.text(owner).to_owned(),
                    name: name.to_owned(),
                },
                _ => unknown,
            },
            "parenthesized_expression" | "await_expression" => node
                .named_child(0)
                .map_or(unknown, |inner| self.source(inner)),
            "cast_expression" => node
                .child_by_field_name("value")
                .map_or(unknown, |inner| self.source(inner)),
            "binary_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| self.text(op) == "+") =>
            {
                let parts = ["left", "right"]
                    .iter()
                    .filter_map(|f| node.child_by_field_name(f))
                    .map(|part| self.pending(part))
                    .collect();
                ArgSource::Concat(parts)
            }
            "conditional_expression" => ArgSource::Choice(
                ["consequence", "alternative"]
                    .iter()
                    .filter_map(|f| node.child_by_field_name(f))
                    .map(|branch| self.pending(branch))
                    .collect(),
            ),
            // `s switch { "a" => "RSA", _ => "EC" }`: the value of each arm.
            "switch_expression" => ArgSource::Choice(
                node.named_children(&mut cursor)
                    .filter(|arm| arm.kind() == "switch_expression_arm")
                    .filter_map(|arm| arm.named_child(arm.named_child_count().checked_sub(1)?))
                    .map(|value| self.pending(value))
                    .collect(),
            ),
            "invocation_expression" => {
                let Some((object, method)) = invoked(node, self.src) else {
                    return unknown;
                };
                let method = method.to_owned();
                let args = self.args(node);
                match object {
                    // A method of this file.
                    None => ArgSource::Call { method, args },
                    Some(o) if self.is_this(o) => ArgSource::Call { method, args },
                    // Another type's method, by the receiver's type.
                    Some(o) => match self.receiver(o, 0) {
                        Some(receiver @ (Receiver::Name(_) | Receiver::Path(_))) => {
                            ArgSource::MemberCall {
                                receiver,
                                method,
                                args,
                            }
                        }
                        _ => unknown,
                    },
                }
            }
            _ => unknown,
        }
    }

    fn literal(&self, node: Node<'_>) -> Option<ArgValue> {
        let text = self.text(node);
        match node.kind() {
            "string_literal" | "verbatim_string_literal" | "raw_string_literal" => {
                string_value(text).map(ArgValue::Str)
            }
            "integer_literal" => int_value(text).map(ArgValue::Int),
            _ => None,
        }
    }

    fn defer(&mut self, pending: Pending, scope: ScopeId, node: Node<'_>) {
        let location = self.location(node);
        self.file.defer(pending, scope, location);
    }

    fn ready(&mut self, kind: FactKind, scope: ScopeId, node: Node<'_>) {
        self.defer(Pending::Ready(kind), scope, node);
    }

    fn text(&self, node: Node<'_>) -> &'s str {
        &self.src[node.byte_range()]
    }

    fn field_text(&self, node: Node<'_>, field: &str) -> Option<&'s str> {
        node.child_by_field_name(field).map(|n| self.text(n))
    }

    fn location(&self, node: Node<'_>) -> Location {
        span::location(self.src, node)
    }
}
