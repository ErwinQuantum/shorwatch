//! Java frontend (tree-sitter-java).
//!
//! Lowering happens in two phases. A single traversal records scopes, imports,
//! declarations and *pending* facts whose names are still unresolved. Once the
//! whole file is known (fields may be declared after the methods using them),
//! pending facts are resolved: receivers to their declared types, identifier
//! arguments to the literal value of `final` constants.
//!
//! What this deliberately does not do: data flow. A value that only reaches a
//! crypto API through a non-final variable, a method call or another file is
//! reported as unknown. That is the job of the future taint-analysis layer.
//!
//! - this module: the traversal (phase one) and node helpers;
//! - [`resolve`]: phase two, names to types, constant and injected values;
//! - [`literals`]: decoding Java string and integer literals.

use std::collections::{HashMap, HashSet};

use shorwatch_core::Language;
use shorwatch_core::ir::{ArgValue, FactKind, Location, Position, ScopeId, ScopeKind, SourceUnit};
use tree_sitter::{Node, Parser, Point};

use crate::{Frontend, LangError};
use literals::{int_value, string_value};

mod literals;
mod resolve;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, Default)]
pub struct JavaFrontend;

impl Frontend for JavaFrontend {
    fn language(&self) -> Language {
        Language::Java
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["java"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .map_err(|e| LangError::Grammar(Language::Java, e.to_string()))?;
        // tree-sitter recovers from syntax errors, so a partially broken file
        // still yields facts for the parts that parse.
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| LangError::Parse(path.to_owned()))?;
        Ok(Lowering::new(path, source).run(tree.root_node()))
    }
}

/// What the file says about a name declared in some scope.
#[derive(Debug, Default)]
struct Symbol {
    /// Declared (or, for `var`, inferred) type as written.
    ty: Option<String>,
    /// Literal initializer of a `final` declaration, or the property injected
    /// by `@Value("${...}")`.
    constant: Option<ArgValue>,
}

#[derive(Debug)]
enum Receiver {
    /// `x.m()`: a variable or a type name.
    Name(String),
    /// `a.b.C.m()` or `this.x.m()`.
    Path(String),
}

#[derive(Debug)]
enum ArgSource {
    Value(ArgValue),
    /// `m(NAME)`.
    Name(String),
    /// `m(Owner.NAME)`.
    Member {
        owner: String,
        name: String,
    },
}

#[derive(Debug)]
struct PendingArg {
    source: ArgSource,
    raw: String,
    location: Location,
}

#[derive(Debug)]
enum Pending {
    Call {
        receiver: Option<Receiver>,
        method: String,
        args: Vec<PendingArg>,
    },
    Construct {
        ty: String,
        args: Vec<PendingArg>,
    },
    /// `Owner.NAME`, where `Owner` may turn out to be a variable, not a type.
    Field {
        owner: String,
        name: String,
    },
    /// A bare name that a static import may refer to, unless shadowed.
    StaticMember(String),
    Ready(FactKind),
}

struct Lowering<'s> {
    src: &'s str,
    unit: SourceUnit,
    /// Simple name -> fully qualified name, from single-type imports.
    imports: HashMap<String, String>,
    /// Member name -> fully qualified owner type, from single static imports.
    static_imports: HashMap<String, String>,
    /// Methods declared in this file, which shadow statically imported ones.
    methods: HashSet<String>,
    symbols: HashMap<(ScopeId, String), Symbol>,
    /// Interfaces and annotation types, whose fields are implicitly constant.
    interfaces: HashSet<ScopeId>,
    pending: Vec<(Pending, ScopeId, Location)>,
}

impl<'s> Lowering<'s> {
    fn new(path: &str, src: &'s str) -> Self {
        Self {
            src,
            unit: SourceUnit::new(path, Language::Java),
            imports: HashMap::new(),
            static_imports: HashMap::new(),
            methods: HashSet::new(),
            symbols: HashMap::new(),
            interfaces: HashSet::new(),
            pending: Vec::new(),
        }
    }

    fn run(mut self, root: Node<'_>) -> SourceUnit {
        // Explicit stack: generated Java can nest deeper than the call stack likes.
        let mut stack = vec![(root, SourceUnit::ROOT)];
        let mut cursor = root.walk();
        while let Some((node, scope)) = stack.pop() {
            if let Some(child_scope) = self.visit(node, scope) {
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                stack.extend(children.into_iter().rev().map(|c| (c, child_scope)));
            }
        }
        self.resolve();
        self.unit
    }

    /// Records what `node` contributes. Returns the scope its children belong
    /// to, or `None` when they need no further visiting.
    fn visit(&mut self, node: Node<'_>, scope: ScopeId) -> Option<ScopeId> {
        match node.kind() {
            "line_comment" | "block_comment" => None,
            "import_declaration" => {
                self.import(node, scope);
                None
            }
            kind @ ("class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration") => {
                let name = self.field_text(node, "name").map(str::to_owned);
                let id = self.unit.add_scope(ScopeKind::Type, name, scope);
                if matches!(
                    kind,
                    "interface_declaration" | "annotation_type_declaration"
                ) {
                    self.interfaces.insert(id);
                }
                Some(id)
            }
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration" => {
                let name = self.field_text(node, "name").map(str::to_owned);
                if let Some(name) = &name {
                    self.methods.insert(name.clone());
                }
                Some(self.unit.add_scope(ScopeKind::Method, name, scope))
            }
            "static_initializer" => Some(self.unit.add_scope(
                ScopeKind::Method,
                Some("<clinit>".into()),
                scope,
            )),
            "field_declaration" | "constant_declaration" => {
                let implicit = self.interfaces.contains(&scope);
                self.declare(node, scope, implicit);
                Some(scope)
            }
            "local_variable_declaration" => {
                self.declare(node, scope, false);
                Some(scope)
            }
            "formal_parameter" => {
                if let (Some(ty), Some(name)) = (
                    node.child_by_field_name("type"),
                    self.field_text(node, "name"),
                ) {
                    let symbol = Symbol {
                        ty: Some(type_name(self.text(ty))),
                        constant: self.injected(node),
                    };
                    self.symbols.insert((scope, name.to_owned()), symbol);
                }
                None
            }
            "method_invocation" => {
                self.call(node, scope);
                Some(scope)
            }
            "object_creation_expression" => {
                self.construct(node, scope);
                Some(scope)
            }
            "field_access" => self.field_access(node, scope),
            "identifier" => {
                let name = self.text(node);
                if self.static_imports.contains_key(name) && !is_name_slot(node) {
                    self.defer(Pending::StaticMember(name.to_owned()), scope, node);
                }
                None
            }
            "string_literal" => {
                if let Some(value) = string_value(self.text(node)) {
                    self.ready(FactKind::Literal { value }, scope, node);
                }
                None
            }
            _ => Some(scope),
        }
    }

    fn import(&mut self, node: Node<'_>, scope: ScopeId) {
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        let is_static = children.iter().any(|c| c.kind() == "static");
        let is_wildcard = children.iter().any(|c| c.kind() == "asterisk");
        let Some(name) = children
            .iter()
            .find(|c| matches!(c.kind(), "scoped_identifier" | "identifier"))
        else {
            return;
        };
        let name = self.text(*name).to_owned();
        if !is_wildcard {
            if let Some((owner, simple)) = name.rsplit_once('.') {
                if is_static {
                    self.static_imports
                        .insert(simple.to_owned(), owner.to_owned());
                } else {
                    self.imports.insert(simple.to_owned(), name.clone());
                }
            }
        }
        let path = if is_wildcard {
            format!("{name}.*")
        } else {
            name
        };
        self.ready(FactKind::Import { path }, scope, node);
    }

    fn declare(&mut self, node: Node<'_>, scope: ScopeId, implicitly_final: bool) {
        let declared = node
            .child_by_field_name("type")
            .map(|t| type_name(self.text(t)));
        let is_final = implicitly_final || has_modifier(node, "final");
        let injected = self.injected(node);
        let mut cursor = node.walk();
        let declarators: Vec<_> = node
            .children_by_field_name("declarator", &mut cursor)
            .collect();
        for declarator in declarators {
            let Some(name) = self.field_text(declarator, "name") else {
                continue;
            };
            let value = declarator.child_by_field_name("value");
            let ty = match declared.as_deref() {
                Some("var") => value.and_then(|v| self.infer_type(v)),
                other => other.map(str::to_owned),
            };
            let constant = match (&injected, is_final) {
                (Some(injected), _) => Some(injected.clone()),
                (None, true) => value.and_then(|v| self.literal(v)),
                (None, false) => None,
            };
            self.symbols
                .insert((scope, name.to_owned()), Symbol { ty, constant });
        }
    }

    /// `@Value("${key}")` or `@Value("${key:default}")` on a declaration
    /// (Spring). SpEL (`#{...}`) and composite strings are not interpreted.
    fn injected(&self, declaration: Node<'_>) -> Option<ArgValue> {
        let mut cursor = declaration.walk();
        let modifiers = declaration
            .children(&mut cursor)
            .find(|c| c.kind() == "modifiers")?;
        let mut cursor = modifiers.walk();
        let annotation = modifiers.children(&mut cursor).find(|a| {
            a.kind() == "annotation"
                && self
                    .field_text(*a, "name")
                    .is_some_and(|n| n == "Value" || n.ends_with(".Value"))
        })?;
        let arguments = annotation.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        let literal = arguments
            .named_children(&mut cursor)
            .find(|n| n.kind() == "string_literal")?;
        let text = string_value(self.text(literal))?;
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

    /// Type of a `var` initializer, when it is obvious from the syntax.
    fn infer_type(&self, value: Node<'_>) -> Option<String> {
        match value.kind() {
            "object_creation_expression" | "cast_expression" => value
                .child_by_field_name("type")
                .map(|t| type_name(self.text(t))),
            // `Cipher.getInstance(...)`: JCA factories return their own type.
            "method_invocation" => {
                let object = value.child_by_field_name("object")?;
                let text = self.text(object);
                (object.kind() == "identifier" && starts_uppercase(text)).then(|| text.to_owned())
            }
            _ => None,
        }
    }

    fn call(&mut self, node: Node<'_>, scope: ScopeId) {
        let Some(method) = self.field_text(node, "name").map(str::to_owned) else {
            return;
        };
        let receiver = node.child_by_field_name("object").and_then(|object| {
            let text = self.text(object).to_owned();
            match object.kind() {
                "identifier" => Some(Receiver::Name(text)),
                "field_access" | "scoped_identifier" => Some(Receiver::Path(text)),
                _ => None,
            }
        });
        let args = self.args(node);
        self.defer(
            Pending::Call {
                receiver,
                method,
                args,
            },
            scope,
            node,
        );
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

    /// `Owner.NAME`. A pure name path (`a.b.C.NAME`) has nothing else inside
    /// to visit; anything else (`call().x`) keeps being traversed.
    fn field_access(&mut self, node: Node<'_>, scope: ScopeId) -> Option<ScopeId> {
        let (object, name) = (
            node.child_by_field_name("object")?,
            self.field_text(node, "field")?,
        );
        if !is_name_path(object) {
            return Some(scope);
        }
        let owner: String = self.text(object).split_whitespace().collect();
        let name = name.to_owned();
        self.defer(Pending::Field { owner, name }, scope, node);
        None
    }

    fn args(&self, node: Node<'_>) -> Vec<PendingArg> {
        let Some(list) = node.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut cursor = list.walk();
        list.named_children(&mut cursor)
            .filter(|arg| !matches!(arg.kind(), "line_comment" | "block_comment"))
            .map(|arg| {
                let source = match (self.literal(arg), arg.kind()) {
                    (Some(value), _) => ArgSource::Value(value),
                    (None, "identifier") => ArgSource::Name(self.text(arg).to_owned()),
                    (None, "field_access") => match (
                        arg.child_by_field_name("object"),
                        self.field_text(arg, "field"),
                    ) {
                        (Some(owner), Some(name)) => ArgSource::Member {
                            owner: self.text(owner).to_owned(),
                            name: name.to_owned(),
                        },
                        _ => ArgSource::Value(ArgValue::Unknown),
                    },
                    _ => ArgSource::Value(ArgValue::Unknown),
                };
                PendingArg {
                    source,
                    raw: self.text(arg).to_owned(),
                    location: self.location(arg),
                }
            })
            .collect()
    }

    fn literal(&self, node: Node<'_>) -> Option<ArgValue> {
        let text = self.text(node);
        match node.kind() {
            "string_literal" => string_value(text).map(ArgValue::Str),
            "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal" => int_value(text).map(ArgValue::Int),
            _ => None,
        }
    }

    fn defer(&mut self, pending: Pending, scope: ScopeId, node: Node<'_>) {
        let location = self.location(node);
        self.pending.push((pending, scope, location));
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
        Location {
            start: self.position(node.start_byte(), node.start_position()),
            end: self.position(node.end_byte(), node.end_position()),
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        }
    }

    /// tree-sitter columns are byte offsets; SARIF wants code points.
    fn position(&self, byte: usize, point: Point) -> Position {
        let line_start = byte - point.column;
        let column = self
            .src
            .get(line_start..byte)
            .map_or(point.column, |s| s.chars().count());
        Position {
            line: u32::try_from(point.row + 1).unwrap_or(u32::MAX),
            column: u32::try_from(column + 1).unwrap_or(u32::MAX),
        }
    }
}

fn has_modifier(node: Node<'_>, modifier: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|c| c.kind() == "modifiers")
        .any(|modifiers| {
            let mut inner = modifiers.walk();
            modifiers.children(&mut inner).any(|m| m.kind() == modifier)
        })
}

/// `a`, `this.x`, `a.b.C`: nothing but names, so nothing inside to analyze.
fn is_name_path(node: Node<'_>) -> bool {
    match node.kind() {
        "identifier" | "this" | "super" => true,
        "field_access" => node.child_by_field_name("object").is_some_and(is_name_path),
        _ => false,
    }
}

/// Whether `node` is the name slot of its parent (a declaration, an invoked
/// method, a selected field) rather than an expression with a value.
fn is_name_slot(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        ["name", "field"]
            .iter()
            .any(|field| parent.child_by_field_name(field) == Some(node))
    })
}

/// `Map<String, Cipher>[]` -> `Map`. Annotations and generics are dropped.
fn type_name(written: &str) -> String {
    let base = written.split(['<', '[']).next().unwrap_or(written);
    base.split_whitespace().last().unwrap_or(base).to_owned()
}

fn starts_uppercase(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}
