//! Kotlin frontend (tree-sitter-kotlin-ng).
//!
//! Kotlin calls the same JVM libraries as Java, so it lowers into the same
//! facts and the `jvm` rules apply unchanged. The traversal (phase one) is
//! Kotlin's own; resolving names (phase two) is shared with Java in
//! [`crate::jvm`]. Where Kotlin differs:
//!
//! - no `new`: `ECGenParameterSpec(spec)` is a constructor call because the
//!   callee looks like a type name;
//! - member imports (`import com.nimbusds.jose.JWSAlgorithm.RS256`) work like
//!   Java's static imports, and `import ... as Alias` is followed for types;
//! - `val` and `const val` with a literal initializer are constants wherever
//!   they are declared; `companion object` members belong to their class;
//! - scope functions hand their receiver to the lambda:
//!   `KeyGenerator.getInstance("AES").apply { init(128) }` is a call on a
//!   `KeyGenerator`, and so is `it.init(128)` inside `also` or `let`;
//! - string templates with interpolations are not constants; escapes are
//!   decoded, so `@Value("\${jwt.alg}")` reads the property `jwt.alg`.
//!
//! As in Java, there is no data flow: anything else is an unknown value.
//!
//! - this module: the traversal and node helpers;
//! - [`syntax`]: predicates over Kotlin syntax;
//! - [`literals`]: decoding string and integer literals.

use std::collections::HashMap;

use shorwatch_core::Language;
use shorwatch_core::ir::{ArgValue, FactKind, Location, ScopeId, ScopeKind, SourceUnit};
use tree_sitter::{Node, Parser};

use crate::jvm::{
    ArgSource, Assignment, JvmFile, Pending, PendingArg, Receiver, Symbol, starts_uppercase,
};
use crate::{Frontend, LangError, span};
use literals::{TemplatePart, int_value, string_value, template_parts};
use syntax::{
    branch_value, child_of_kind, declared_type, enclosing_calls, has_child, is_name_path, is_value,
    looks_like_type, name_path, navigation_parts, text,
};

mod literals;
mod syntax;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, Default)]
pub struct KotlinFrontend;

impl Frontend for KotlinFrontend {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["kt", "kts"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_kotlin_ng::LANGUAGE.into())
            .map_err(|e| LangError::Grammar(Language::Kotlin, e.to_string()))?;
        // tree-sitter recovers from syntax errors, so a partially broken file
        // still yields facts for the parts that parse.
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| LangError::Parse(path.to_owned()))?;
        Ok(Lowering::new(path, source).run(tree.root_node()))
    }
}

/// Scope functions whose lambda runs with the receiver as `this`.
const RECEIVER_SCOPE_FUNCTIONS: [&str; 2] = ["apply", "run"];
/// Scope functions whose lambda gets the receiver as its parameter (`it`).
const PARAMETER_SCOPE_FUNCTIONS: [&str; 2] = ["also", "let"];

fn is_scope_function(name: &str) -> bool {
    RECEIVER_SCOPE_FUNCTIONS.contains(&name) || PARAMETER_SCOPE_FUNCTIONS.contains(&name)
}

/// What a scope function's lambda knows about its receiver.
#[derive(Debug)]
enum LambdaContext {
    /// `x.apply { m() }`, `with(x) { m() }`: unqualified calls go to `x`.
    Receiver(Receiver),
    /// `x.also { it.m() }`: the lambda's parameter is `x`.
    Parameter {
        ty: Option<String>,
        origin: Option<Vec<PendingArg>>,
    },
}

struct Lowering<'s> {
    src: &'s str,
    file: JvmFile,
    /// Scope-function lambdas met before their scope exists, by node id.
    lambdas: HashMap<usize, LambdaContext>,
    /// Implicit receivers of lambda scopes.
    implicit: HashMap<ScopeId, Receiver>,
}

impl<'s> Lowering<'s> {
    fn new(path: &str, src: &'s str) -> Self {
        Self {
            src,
            file: JvmFile::new(path, Language::Kotlin),
            lambdas: HashMap::new(),
            implicit: HashMap::new(),
        }
    }

    fn run(mut self, root: Node<'_>) -> SourceUnit {
        // Explicit stack: deeply nested DSLs would strain the call stack.
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
            "package_header" => {
                if let Some(path) = child_of_kind(node, "qualified_identifier") {
                    let mut cursor = path.walk();
                    let segments: Vec<&str> = path
                        .named_children(&mut cursor)
                        .map(|s| self.text(s))
                        .collect();
                    self.file.package = segments.join(".");
                }
                None
            }
            "line_comment"
            | "block_comment"
            | "variable_declaration"
            | "user_type"
            | "nullable_type"
            | "parameter" => None,
            "import" => {
                self.import(node, scope);
                None
            }
            "class_declaration" | "object_declaration" => {
                let name = self.field_text(node, "name").map(str::to_owned);
                let id = self.file.unit.add_scope(ScopeKind::Type, name, scope);
                let supertypes = self.supertypes(node);
                self.file.type_decls.push((id, supertypes));
                Some(id)
            }
            "function_declaration" => {
                let name = self.field_text(node, "name").map(str::to_owned);
                if let Some(name) = &name {
                    self.file.methods.insert(name.clone());
                }
                let id = self.file.unit.add_scope(ScopeKind::Method, name, scope);
                if let Some(ty) = self.return_type(node) {
                    self.file.return_types.insert(id, ty);
                }
                Some(id)
            }
            "secondary_constructor" | "anonymous_initializer" => Some(self.file.unit.add_scope(
                ScopeKind::Method,
                Some("<init>".into()),
                scope,
            )),
            "lambda_literal" => Some(self.lambda(node, scope)),
            "property_declaration" => {
                self.declare_property(node, scope);
                Some(scope)
            }
            "class_parameter" => {
                self.declare(node, scope, self.injected(node));
                // The primary constructor's parameters belong to the class.
                if let Some(name) = child_of_kind(node, "identifier") {
                    let name = self.text(name).to_owned();
                    self.file.params.entry(scope).or_default().push(name);
                }
                Some(scope)
            }
            "function_value_parameters" => {
                self.declare_parameters(node, scope);
                Some(scope)
            }
            // `fun f() = expression`: an expression body is a return.
            "function_body" => {
                if let Some(value) = node.named_child(0).filter(|v| v.kind() != "block") {
                    let value = self.pending(value);
                    self.file.returns.push((scope, value));
                }
                Some(scope)
            }
            "return_expression" => {
                if let Some(value) = node.named_child(0) {
                    let value = self.pending(value);
                    self.file.returns.push((scope, value));
                }
                Some(scope)
            }
            "assignment" => {
                self.assign(node, scope);
                Some(scope)
            }
            "call_expression" => {
                self.call(node, scope);
                Some(scope)
            }
            "navigation_expression" => self.navigation(node, scope),
            "identifier" => {
                let name = self.text(node);
                if self.file.static_imports.contains_key(name) && is_value(node) {
                    self.defer(Pending::StaticMember(name.to_owned()), scope, node);
                }
                None
            }
            "string_literal" | "multiline_string_literal" => {
                if let Some(value) = string_value(node, self.src) {
                    let calls = enclosing_calls(node, self.src);
                    self.ready(FactKind::Literal { value, calls }, scope, node);
                }
                // Interpolations may hold calls.
                Some(scope)
            }
            _ => Some(scope),
        }
    }

    fn import(&mut self, node: Node<'_>, scope: ScopeId) {
        let Some(path) = child_of_kind(node, "qualified_identifier") else {
            return;
        };
        let mut cursor = path.walk();
        let segments: Vec<&str> = path
            .named_children(&mut cursor)
            .map(|s| self.text(s))
            .collect();
        let name = segments.join(".");
        if has_child(node, "*") {
            self.file.on_demand_imports.push(name.clone());
            self.ready(
                FactKind::Import {
                    path: format!("{name}.*"),
                },
                scope,
                node,
            );
            return;
        }
        let alias = child_of_kind(node, "identifier").map(|a| self.text(a));
        if let [.., owner_name, member] = segments.as_slice() {
            // `...JWSAlgorithm.RS256`, `...Algorithm.RSA256`: a member of a
            // class. `...Map.Entry` is a nested type.
            let is_member = starts_uppercase(owner_name) && !looks_like_type(member);
            if is_member {
                // An aliased member would resolve under the wrong name.
                if alias.is_none() {
                    let owner = segments[..segments.len() - 1].join(".");
                    self.file.static_imports.insert((*member).to_owned(), owner);
                }
            } else {
                let simple = alias.unwrap_or(member);
                self.file.imports.insert(simple.to_owned(), name.clone());
            }
        }
        self.ready(FactKind::Import { path: name }, scope, node);
    }

    /// `val NAME = "RSA"` / `var x: Cipher = ...`, with `@Value` injection.
    fn declare_property(&mut self, node: Node<'_>, scope: ScopeId) {
        let Some(variable) = child_of_kind(node, "variable_declaration") else {
            return;
        };
        let Some(name) = child_of_kind(variable, "identifier").map(|n| self.text(n)) else {
            return;
        };
        let value = self.initializer(node, variable);
        let ty = declared_type(variable, self.src)
            .or_else(|| value.and_then(|v| self.infer_type(v, scope)));
        let constant = self.injected(node).or_else(|| {
            has_child(node, "val")
                .then(|| value.and_then(|v| self.literal(v)))
                .flatten()
        });
        let origin = value.and_then(|v| self.origin(v, scope));
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
                ty,
                constant,
                origin,
            },
        );
    }

    /// The expression after `=` in a property declaration.
    fn initializer<'t>(&self, node: Node<'t>, variable: Node<'t>) -> Option<Node<'t>> {
        let mut cursor = node.walk();
        let mut after = node
            .named_children(&mut cursor)
            .skip_while(|c| *c != variable)
            .skip(1);
        after.find(|c| {
            !matches!(
                c.kind(),
                "getter"
                    | "setter"
                    | "property_delegate"
                    | "type_constraints"
                    | "line_comment"
                    | "block_comment"
            )
        })
    }

    /// A primary-constructor or function parameter, named by its first
    /// identifier.
    fn declare(&mut self, node: Node<'_>, scope: ScopeId, injected: Option<ArgValue>) {
        let Some(name) = child_of_kind(node, "identifier").map(|n| self.text(n)) else {
            return;
        };
        let symbol = Symbol {
            ty: declared_type(node, self.src),
            constant: injected,
            origin: None,
        };
        self.file.symbols.insert((scope, name.to_owned()), symbol);
    }

    /// Function parameters. Their annotations are siblings that precede them.
    fn declare_parameters(&mut self, node: Node<'_>, scope: ScopeId) {
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        let mut annotations = None;
        for child in children {
            match child.kind() {
                "parameter_modifiers" => annotations = Some(child),
                "parameter" => {
                    let injected = annotations.take().and_then(|m| self.value_annotation(m));
                    self.declare(child, scope, injected);
                    if let Some(name) = child_of_kind(child, "identifier") {
                        let name = self.text(name).to_owned();
                        self.file.params.entry(scope).or_default().push(name);
                    }
                }
                _ => {}
            }
        }
    }

    /// `@Value("\${key}")` in a declaration's modifiers.
    fn injected(&self, declaration: Node<'_>) -> Option<ArgValue> {
        self.value_annotation(child_of_kind(declaration, "modifiers")?)
    }

    /// `@Value("\${key}")` or `@Value("\${key:default}")` among `modifiers`
    /// (Spring). SpEL (`#{...}`) and templates are not interpreted.
    fn value_annotation(&self, modifiers: Node<'_>) -> Option<ArgValue> {
        let mut cursor = modifiers.walk();
        let invocation = modifiers
            .named_children(&mut cursor)
            .filter(|a| a.kind() == "annotation")
            .filter_map(|a| child_of_kind(a, "constructor_invocation"))
            .find(|invocation| {
                child_of_kind(*invocation, "user_type")
                    .and_then(|t| syntax::type_name(t, self.src))
                    .is_some_and(|n| n == "Value" || n.ends_with(".Value"))
            })?;
        let argument = child_of_kind(
            child_of_kind(invocation, "value_arguments")?,
            "value_argument",
        )?;
        let literal = argument.named_child(argument.named_child_count().checked_sub(1)?)?;
        let ArgValue::Str(text) = self.literal(literal)? else {
            return None;
        };
        let inner = text.strip_prefix("${")?.strip_suffix('}')?;
        let (key, default) = match inner.split_once(':') {
            Some((key, default)) => (key, Some(default.to_owned())),
            None => (inner, None),
        };
        Some(ArgValue::Injected {
            key: key.to_owned(),
            default,
            resolved: Vec::new(),
        })
    }

    /// Type of an initializer or receiver expression, when the syntax shows it.
    fn infer_type(&self, value: Node<'_>, scope: ScopeId) -> Option<String> {
        match value.kind() {
            "call_expression" => {
                let callee = value.named_child(0)?;
                match callee.kind() {
                    // `Cipher(...)`: a constructor.
                    "identifier" => {
                        let name = self.text(callee);
                        looks_like_type(name).then(|| name.to_owned())
                    }
                    "navigation_expression" => {
                        let (object, member) = navigation_parts(callee)?;
                        let member = self.text(member);
                        if is_scope_function(member) {
                            // `apply` and `also` return their receiver.
                            return self.infer_type(object, scope);
                        }
                        if !is_name_path(object) {
                            return None;
                        }
                        let path = name_path(object, self.src);
                        if looks_like_type(member) {
                            // `java.security.spec.ECGenParameterSpec(...)`.
                            Some(format!("{path}.{member}"))
                        } else {
                            // `Cipher.getInstance(...)`: JCA factories return
                            // their own type.
                            let last = path.rsplit('.').next().unwrap_or(&path);
                            starts_uppercase(last).then_some(path)
                        }
                    }
                    _ => None,
                }
            }
            "identifier" => self.file.lookup(scope, self.text(value))?.ty.clone(),
            "navigation_expression" => {
                let (object, member) = navigation_parts(value)?;
                (object.kind() == "this_expression")
                    .then(|| self.file.lookup(scope, self.text(member))?.ty.clone())
                    .flatten()
            }
            _ => None,
        }
    }

    /// What a scope function hands to its lambda, given the receiver.
    fn receiver(&self, object: Node<'_>, scope: ScopeId) -> Option<Receiver> {
        match object.kind() {
            "identifier" => Some(Receiver::Name(self.text(object).to_owned())),
            _ if is_name_path(object) => Some(Receiver::Path(name_path(object, self.src))),
            _ => self.infer_type(object, scope).map(|ty| Receiver::Type {
                ty,
                origin: self.origin(object, scope),
            }),
        }
    }

    /// Arguments of the factory call `value` comes from
    /// (`KeyGenerator.getInstance("AES")`), also through scope functions
    /// (`...getInstance("AES").apply { }`) and variables initialized by one.
    fn origin(&self, value: Node<'_>, scope: ScopeId) -> Option<Vec<PendingArg>> {
        match value.kind() {
            "call_expression" => {
                let (object, member) = navigation_parts(value.named_child(0)?)?;
                let member = self.text(member);
                if is_scope_function(member) {
                    return self.origin(object, scope);
                }
                if !is_name_path(object) || looks_like_type(member) {
                    return None;
                }
                let path = name_path(object, self.src);
                let owner = path.rsplit('.').next().unwrap_or(&path);
                starts_uppercase(owner).then(|| self.args(value))
            }
            "identifier" => self.file.lookup(scope, self.text(value))?.origin.clone(),
            _ => None,
        }
    }

    fn lambda(&mut self, node: Node<'_>, scope: ScopeId) -> ScopeId {
        let id = self
            .file
            .unit
            .add_scope(ScopeKind::Method, Some("<lambda>".into()), scope);
        match self.lambdas.remove(&node.id()) {
            Some(LambdaContext::Receiver(receiver)) => {
                self.implicit.insert(id, receiver);
            }
            Some(LambdaContext::Parameter { ty, origin }) => {
                let name = child_of_kind(node, "lambda_parameters")
                    .and_then(|p| child_of_kind(p, "variable_declaration"))
                    .and_then(|v| child_of_kind(v, "identifier"))
                    .map_or("it", |n| self.text(n));
                self.file.symbols.insert(
                    (id, name.to_owned()),
                    Symbol {
                        ty,
                        constant: None,
                        origin,
                    },
                );
            }
            None => {}
        }
        id
    }

    /// Remembers what the trailing lambda of a scope-function call receives.
    fn scope_function(&mut self, call: Node<'_>, context: LambdaContext) {
        if let Some(lambda) =
            child_of_kind(call, "annotated_lambda").and_then(|a| child_of_kind(a, "lambda_literal"))
        {
            self.lambdas.insert(lambda.id(), context);
        }
    }

    fn call(&mut self, node: Node<'_>, scope: ScopeId) {
        let Some(callee) = node.named_child(0) else {
            return;
        };
        let has_lambda = child_of_kind(node, "annotated_lambda").is_some();
        match callee.kind() {
            "identifier" => {
                let name = self.text(callee).to_owned();
                if self.file.static_imports.contains_key(&name) {
                    // Resolved to the imported owner unless a local function
                    // shadows it.
                    let args = self.args(node);
                    self.defer(
                        Pending::Call {
                            receiver: None,
                            method: name,
                            args,
                        },
                        scope,
                        node,
                    );
                } else if looks_like_type(&name) {
                    let args = self.args(node);
                    self.defer(Pending::Construct { ty: name, args }, scope, node);
                } else {
                    let receiver = self.implicit_receiver(scope);
                    let args = self.args(node);
                    self.defer(
                        Pending::Call {
                            receiver,
                            method: name,
                            args,
                        },
                        scope,
                        node,
                    );
                }
            }
            // `with(x) { ... }`: the callee is itself the call `with(x)`.
            "call_expression" if has_lambda => {
                let inner = callee;
                let is_with = inner
                    .named_child(0)
                    .is_some_and(|c| c.kind() == "identifier" && self.text(c) == "with");
                let object = child_of_kind(inner, "value_arguments")
                    .and_then(|a| child_of_kind(a, "value_argument"))
                    .and_then(|a| a.named_child(a.named_child_count().checked_sub(1)?));
                if let (true, Some(object)) = (is_with, object)
                    && let Some(receiver) = self.receiver(object, scope)
                {
                    self.scope_function(node, LambdaContext::Receiver(receiver));
                }
            }
            "navigation_expression" => {
                let Some((object, member)) = navigation_parts(callee) else {
                    return;
                };
                let method = self.text(member).to_owned();
                if has_lambda && RECEIVER_SCOPE_FUNCTIONS.contains(&method.as_str()) {
                    if let Some(receiver) = self.receiver(object, scope) {
                        self.scope_function(node, LambdaContext::Receiver(receiver));
                    }
                    return;
                }
                if has_lambda && PARAMETER_SCOPE_FUNCTIONS.contains(&method.as_str()) {
                    let context = LambdaContext::Parameter {
                        ty: self.infer_type(object, scope),
                        origin: self.origin(object, scope),
                    };
                    self.scope_function(node, context);
                    return;
                }
                let args = self.args(node);
                if !is_name_path(object) {
                    // `Crypto.provider().m()`: typed from `provider()` later.
                    let receiver = self.chained(object);
                    self.defer(
                        Pending::Call {
                            receiver,
                            method,
                            args,
                        },
                        scope,
                        node,
                    );
                } else if looks_like_type(&method) {
                    let ty = format!("{}.{method}", name_path(object, self.src));
                    self.defer(Pending::Construct { ty, args }, scope, node);
                } else {
                    let receiver = match object.kind() {
                        "identifier" => Receiver::Name(self.text(object).to_owned()),
                        _ => Receiver::Path(name_path(object, self.src)),
                    };
                    self.defer(
                        Pending::Call {
                            receiver: Some(receiver),
                            method,
                            args,
                        },
                        scope,
                        node,
                    );
                }
            }
            _ => {}
        }
    }

    /// `object` as the receiver of a chained call, when it is a call to a
    /// named method: `provider()` or `Crypto.provider()`.
    fn chained(&self, object: Node<'_>) -> Option<Receiver> {
        if object.kind() != "call_expression" {
            return None;
        }
        let callee = object.named_child(0)?;
        let arity = self.args(object).len();
        let (owner, method) = match callee.kind() {
            "identifier" => (None, self.text(callee)),
            "navigation_expression" => {
                let (owner, member) = navigation_parts(callee)?;
                let owner = match owner.kind() {
                    "identifier" => Receiver::Name(self.text(owner).to_owned()),
                    _ if is_name_path(owner) => Receiver::Path(name_path(owner, self.src)),
                    _ => return None,
                };
                (Some(Box::new(owner)), self.text(member))
            }
            _ => return None,
        };
        (!looks_like_type(method) && !is_scope_function(method)).then(|| Receiver::Call {
            owner,
            method: method.to_owned(),
            arity,
        })
    }

    /// The types a class or object extends or implements, as written.
    fn supertypes(&self, declaration: Node<'_>) -> Vec<String> {
        let Some(specifiers) = child_of_kind(declaration, "delegation_specifiers") else {
            return Vec::new();
        };
        let mut cursor = specifiers.walk();
        specifiers
            .named_children(&mut cursor)
            .filter_map(|specifier| {
                let ty = child_of_kind(specifier, "user_type").or_else(|| {
                    child_of_kind(specifier, "constructor_invocation")
                        .and_then(|c| child_of_kind(c, "user_type"))
                })?;
                syntax::type_name(ty, self.src)
            })
            .collect()
    }

    /// A function's declared return type: the type after its parameters.
    fn return_type(&self, function: Node<'_>) -> Option<String> {
        let mut cursor = function.walk();
        let ty = function
            .named_children(&mut cursor)
            .skip_while(|c| c.kind() != "function_value_parameters")
            .find(|c| matches!(c.kind(), "user_type" | "nullable_type"))?;
        syntax::type_name(ty, self.src)
    }

    /// The receiver of unqualified calls inside `apply`, `run` or `with`.
    fn implicit_receiver(&self, mut scope: ScopeId) -> Option<Receiver> {
        loop {
            if let Some(receiver) = self.implicit.get(&scope) {
                return Some(receiver.clone());
            }
            scope = self.file.unit.scope(scope).parent?;
        }
    }

    /// `Owner.NAME` read as a value. The callee of a call is the call's
    /// business; a pure name path has nothing else inside to visit.
    fn navigation(&mut self, node: Node<'_>, scope: ScopeId) -> Option<ScopeId> {
        let (object, member) = navigation_parts(node)?;
        if !is_name_path(object) {
            return Some(scope);
        }
        let is_callee = node
            .parent()
            .is_some_and(|p| p.kind() == "call_expression" && p.named_child(0) == Some(node));
        if is_callee {
            // `Jwks.CRV.P384.keyPair()`: the call's object is itself a read.
            return (object.kind() == "navigation_expression").then_some(scope);
        }
        let owner = name_path(object, self.src);
        let name = self.text(member).to_owned();
        self.defer(Pending::Field { owner, name }, scope, node);
        None
    }

    /// `name = value` or `this.name = value`, for data flow.
    fn assign(&mut self, node: Node<'_>, scope: ScopeId) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        // Compound assignments (`+=`) are not values of their own.
        let mut cursor = node.walk();
        let is_plain = node
            .children(&mut cursor)
            .any(|c| !c.is_named() && self.text(c) == "=");
        let target = match left.kind() {
            "identifier" => Some((self.text(left), false)),
            "navigation_expression" => navigation_parts(left)
                .filter(|(owner, _)| owner.kind() == "this_expression")
                .map(|(_, name)| (self.text(name), true)),
            _ => None,
        };
        if let (true, Some((name, field))) = (is_plain, target) {
            self.file.assignments.push(Assignment {
                scope,
                name: name.to_owned(),
                field,
                value: self.pending(right),
                location: self.location(node),
            });
        }
    }

    fn args(&self, node: Node<'_>) -> Vec<PendingArg> {
        let Some(list) = child_of_kind(node, "value_arguments") else {
            return Vec::new();
        };
        let mut cursor = list.walk();
        list.named_children(&mut cursor)
            .filter(|a| a.kind() == "value_argument")
            // `name = value`: the label is not the value.
            .filter_map(|a| a.named_child(a.named_child_count().checked_sub(1)?))
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
            "string_literal" | "multiline_string_literal" => {
                let Some(parts) = template_parts(node, self.src) else {
                    return unknown;
                };
                let location = self.location(node);
                ArgSource::Concat(
                    parts
                        .into_iter()
                        .map(|part| {
                            let (source, raw) = match part {
                                TemplatePart::Text(text) => {
                                    (ArgSource::Value(ArgValue::Str(text.clone())), text)
                                }
                                TemplatePart::Name(name) => (ArgSource::Name(name.clone()), name),
                                TemplatePart::Unknown => {
                                    (ArgSource::Value(ArgValue::Unknown), String::new())
                                }
                            };
                            PendingArg {
                                source,
                                raw,
                                location,
                            }
                        })
                        .collect(),
                )
            }
            "identifier" => ArgSource::Name(self.text(node).to_owned()),
            "navigation_expression" => match navigation_parts(node) {
                Some((owner, name)) if owner.kind() == "this_expression" => ArgSource::Member {
                    owner: "this".to_owned(),
                    name: self.text(name).to_owned(),
                },
                Some((owner, name)) if is_name_path(owner) => ArgSource::Member {
                    owner: name_path(owner, self.src),
                    name: self.text(name).to_owned(),
                },
                _ => unknown,
            },
            "parenthesized_expression" => node
                .named_child(0)
                .map_or(unknown, |inner| self.source(inner)),
            "binary_expression"
                if node
                    .children(&mut cursor)
                    .any(|c| !c.is_named() && self.text(c) == "+") =>
            {
                let parts = ["left", "right"]
                    .iter()
                    .filter_map(|f| node.child_by_field_name(f))
                    .map(|part| self.pending(part))
                    .collect();
                ArgSource::Concat(parts)
            }
            // `if (c) "RSA" else "EC"`: the branches after the condition.
            "if_expression" => {
                let condition = node.child_by_field_name("condition");
                ArgSource::Choice(
                    node.named_children(&mut cursor)
                        .filter(|c| Some(*c) != condition)
                        .map(|branch| self.pending(branch_value(branch)))
                        .collect(),
                )
            }
            // `when (x) { A -> "RSA"; else -> "EC" }`: each entry's value.
            "when_expression" => ArgSource::Choice(
                node.named_children(&mut cursor)
                    .filter(|e| e.kind() == "when_entry")
                    .filter_map(|e| e.named_child(e.named_child_count().checked_sub(1)?))
                    .map(|value| self.pending(branch_value(value)))
                    .collect(),
            ),
            "call_expression" => match node.named_child(0) {
                // A function of this file.
                Some(callee)
                    if callee.kind() == "identifier" && !looks_like_type(self.text(callee)) =>
                {
                    ArgSource::Call {
                        method: self.text(callee).to_owned(),
                        args: self.args(node),
                    }
                }
                // Another type's function, by the receiver's type.
                Some(callee) if callee.kind() == "navigation_expression" => {
                    let Some((object, member)) = navigation_parts(callee) else {
                        return unknown;
                    };
                    let method = self.text(member).to_owned();
                    let receiver = match object.kind() {
                        "this_expression" => None,
                        "identifier" => Some(Receiver::Name(self.text(object).to_owned())),
                        _ if is_name_path(object) => {
                            Some(Receiver::Path(name_path(object, self.src)))
                        }
                        _ => return unknown,
                    };
                    if looks_like_type(&method) || is_scope_function(&method) {
                        return unknown;
                    }
                    let args = self.args(node);
                    match receiver {
                        None => ArgSource::Call { method, args },
                        Some(receiver) => ArgSource::MemberCall {
                            receiver,
                            method,
                            args,
                        },
                    }
                }
                _ => unknown,
            },
            _ => unknown,
        }
    }

    fn literal(&self, node: Node<'_>) -> Option<ArgValue> {
        match node.kind() {
            "string_literal" | "multiline_string_literal" => {
                string_value(node, self.src).map(ArgValue::Str)
            }
            "number_literal" => int_value(self.text(node)).map(ArgValue::Int),
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
        text(node, self.src)
    }

    fn field_text(&self, node: Node<'_>, field: &str) -> Option<&'s str> {
        node.child_by_field_name(field).map(|n| self.text(n))
    }

    fn location(&self, node: Node<'_>) -> Location {
        span::location(self.src, node)
    }
}
