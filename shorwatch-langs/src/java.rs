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

use std::collections::{HashMap, HashSet};

use shorwatch_core::Language;
use shorwatch_core::ir::{
    Arg, ArgValue, FactKind, Location, Position, ScopeId, ScopeKind, SourceUnit, TypeRef,
};
use tree_sitter::{Node, Parser, Point};

use crate::{Frontend, LangError};

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
    /// Literal initializer of a `final` declaration.
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
                        constant: None,
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
            let constant = if is_final {
                value.and_then(|v| self.literal(v))
            } else {
                None
            };
            self.symbols
                .insert((scope, name.to_owned()), Symbol { ty, constant });
        }
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

    fn resolve(&mut self) {
        for (pending, scope, location) in std::mem::take(&mut self.pending) {
            let kind = match pending {
                Pending::Call {
                    receiver,
                    method,
                    args,
                } => FactKind::Call {
                    receiver: match receiver {
                        Some(r) => self.resolve_receiver(&r, scope),
                        None => self.static_method_owner(&method),
                    },
                    method,
                    args: self.resolve_args(args, scope),
                },
                Pending::Construct { ty, args } => FactKind::Construct {
                    ty: self.type_ref(&ty),
                    args: self.resolve_args(args, scope),
                },
                Pending::Field { owner, name } => match self.field_owner(&owner, scope) {
                    Some(owner) => FactKind::Field { owner, name },
                    None => continue,
                },
                Pending::StaticMember(name) => {
                    if self.lookup(scope, &name).is_some() {
                        continue;
                    }
                    let owner = TypeRef::qualified(self.static_imports[&name].clone());
                    FactKind::Field { owner, name }
                }
                Pending::Ready(kind) => kind,
            };
            self.unit.push(kind, scope, location);
        }
    }

    fn lookup(&self, mut scope: ScopeId, name: &str) -> Option<&Symbol> {
        loop {
            if let Some(symbol) = self.symbols.get(&(scope, name.to_owned())) {
                return Some(symbol);
            }
            scope = self.unit.scope(scope).parent?;
        }
    }

    fn resolve_receiver(&self, receiver: &Receiver, scope: ScopeId) -> Option<TypeRef> {
        let variable_type = |name: &str| {
            self.lookup(scope, name)
                .and_then(|s| s.ty.as_deref())
                .map(|ty| self.type_ref(ty))
        };
        match receiver {
            Receiver::Name(name) => {
                variable_type(name).or_else(|| starts_uppercase(name).then(|| self.type_ref(name)))
            }
            Receiver::Path(path) => match path.strip_prefix("this.") {
                Some(field) if !field.contains('.') => variable_type(field),
                Some(_) => None,
                None => Some(self.type_ref(path)),
            },
        }
    }

    /// Owner of an unqualified call such as `RSA256(...)`, when it comes from a
    /// static import and no method of this file shadows it.
    fn static_method_owner(&self, method: &str) -> Option<TypeRef> {
        if self.methods.contains(method) {
            return None;
        }
        self.static_imports
            .get(method)
            .map(|owner| TypeRef::qualified(owner.clone()))
    }

    /// The type named by `owner` in `owner.NAME`, or `None` when `owner` is a
    /// variable or `this`: then it is an instance field, not a static constant.
    fn field_owner(&self, owner: &str, scope: ScopeId) -> Option<TypeRef> {
        let first = owner.split('.').next().unwrap_or(owner);
        if matches!(first, "this" | "super") || self.lookup(scope, first).is_some() {
            return None;
        }
        owner
            .split('.')
            .any(starts_uppercase)
            .then(|| self.type_ref(owner))
    }

    /// Resolves a type name as written to the most precise [`TypeRef`] possible.
    fn type_ref(&self, name: &str) -> TypeRef {
        match name.split_once('.') {
            // `java.security.KeyPairGenerator`: already fully qualified.
            Some((first, _)) if !starts_uppercase(first) => TypeRef::qualified(name),
            // `Outer.Inner`: qualified only if `Outer` was imported.
            Some((first, rest)) => match self.imports.get(first) {
                Some(outer) => TypeRef::qualified(format!("{outer}.{rest}")),
                None => TypeRef::simple(name.rsplit('.').next().unwrap_or(name)),
            },
            None => match self.imports.get(name) {
                Some(qualified) => TypeRef::qualified(qualified.clone()),
                None => TypeRef::simple(name),
            },
        }
    }

    fn resolve_args(&self, args: Vec<PendingArg>, scope: ScopeId) -> Vec<Arg> {
        args.into_iter()
            .map(
                |PendingArg {
                     source,
                     raw,
                     location,
                 }| {
                    let (value, via_constant) = match source {
                        ArgSource::Value(value) => (Some(value), None),
                        ArgSource::Name(name) => (self.constant(scope, &name), Some(name)),
                        ArgSource::Member { owner, name } => (
                            self.member_constant(scope, &owner, &name),
                            Some(format!("{owner}.{name}")),
                        ),
                    };
                    match value {
                        Some(value) => Arg {
                            value,
                            raw,
                            via_constant,
                            location,
                        },
                        None => Arg {
                            value: ArgValue::Unknown,
                            raw,
                            via_constant: None,
                            location,
                        },
                    }
                },
            )
            .collect()
    }

    fn constant(&self, scope: ScopeId, name: &str) -> Option<ArgValue> {
        self.lookup(scope, name)?.constant.clone()
    }

    /// `Owner.NAME` or `this.NAME`, for owners declared in this file.
    fn member_constant(&self, scope: ScopeId, owner: &str, name: &str) -> Option<ArgValue> {
        if owner == "this" {
            return self.constant(scope, name);
        }
        let owner = owner.rsplit('.').next().unwrap_or(owner);
        self.unit
            .scopes()
            .iter()
            .enumerate()
            .find_map(|(index, s)| {
                let id = ScopeId(u32::try_from(index).ok()?);
                if s.kind == ScopeKind::Type && s.name.as_deref() == Some(owner) {
                    self.symbols.get(&(id, name.to_owned()))?.constant.clone()
                } else {
                    None
                }
            })
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

fn int_value(text: &str) -> Option<i64> {
    let digits: String = text.chars().filter(|c| *c != '_').collect();
    let digits = digits.trim_end_matches(['l', 'L']);
    let lower = digits.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = lower.strip_prefix("0b") {
        i64::from_str_radix(bin, 2).ok()
    } else if lower.len() > 1 && lower.starts_with('0') {
        i64::from_str_radix(&lower[1..], 8).ok()
    } else {
        lower.parse().ok()
    }
}

/// Decoded value of a string literal or text block, as written in `text`.
fn string_value(text: &str) -> Option<String> {
    if let Some(body) = text
        .strip_prefix("\"\"\"")
        .and_then(|t| t.strip_suffix("\"\"\""))
    {
        // Text block content starts on the line after the opening delimiter.
        let body = body.split_once('\n').map_or(body, |(_, rest)| rest);
        return Some(unescape(body));
    }
    let body = text.strip_prefix('"')?.strip_suffix('"')?;
    Some(unescape(body))
}

fn unescape(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('s') => out.push(' '),
            Some('0') => out.push('\0'),
            Some('u') => {
                let hex: String = chars.by_ref().skip_while(|c| *c == 'u').take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(decoded) => out.push(decoded),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(source: &str) -> SourceUnit {
        JavaFrontend.lower("Test.java", source).unwrap()
    }

    fn calls(unit: &SourceUnit) -> Vec<(Option<TypeRef>, String, Vec<ArgValue>)> {
        unit.facts()
            .iter()
            .filter_map(|f| match &f.kind {
                FactKind::Call {
                    receiver,
                    method,
                    args,
                } => Some((
                    receiver.clone(),
                    method.clone(),
                    args.iter().map(|a| a.value.clone()).collect(),
                )),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn lowers_a_static_factory_call() {
        let unit = lower(
            r#"
            import java.security.KeyPairGenerator;
            class A {
                void run() throws Exception {
                    KeyPairGenerator.getInstance("RSA");
                }
            }
            "#,
        );
        assert_eq!(
            calls(&unit),
            [(
                Some(TypeRef::qualified("java.security.KeyPairGenerator")),
                "getInstance".to_owned(),
                vec![ArgValue::Str("RSA".into())]
            )]
        );
    }

    #[test]
    fn resolves_receiver_through_variable_type() {
        let unit = lower(
            r#"
            import javax.crypto.KeyGenerator;
            class A {
                void run() throws Exception {
                    KeyGenerator kg = KeyGenerator.getInstance("AES");
                    kg.init(128);
                    var other = KeyGenerator.getInstance("AES");
                    other.init(256);
                }
            }
            "#,
        );
        let init: Vec<_> = calls(&unit)
            .into_iter()
            .filter(|(_, m, _)| m == "init")
            .collect();
        let kg = TypeRef::qualified("javax.crypto.KeyGenerator");
        assert_eq!(
            init[0],
            (Some(kg.clone()), "init".into(), vec![ArgValue::Int(128)])
        );
        assert_eq!(init[1], (Some(kg), "init".into(), vec![ArgValue::Int(256)]));
    }

    #[test]
    fn resolves_final_constants_declared_after_use() {
        let unit = lower(
            r#"
            class A {
                void run() throws Exception {
                    javax.crypto.Cipher.getInstance(TRANSFORMATION);
                    javax.crypto.Cipher.getInstance(A.TRANSFORMATION);
                    javax.crypto.Cipher.getInstance(mutable);
                }
                private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
                private String mutable = "RSA";
            }
            "#,
        );
        let FactKind::Call { args, .. } = &unit.facts()[0].kind else {
            panic!()
        };
        assert_eq!(args[0].value, ArgValue::Str("RSA/ECB/PKCS1Padding".into()));
        assert_eq!(args[0].via_constant.as_deref(), Some("TRANSFORMATION"));

        let values: Vec<_> = calls(&unit)
            .into_iter()
            .map(|(_, _, a)| a[0].clone())
            .collect();
        assert_eq!(values[1], ArgValue::Str("RSA/ECB/PKCS1Padding".into()));
        assert_eq!(values[2], ArgValue::Unknown);
    }

    #[test]
    fn comments_produce_no_facts() {
        let unit = lower(
            r#"
            class A {
                // KeyPairGenerator.getInstance("RSA");
                /* Cipher.getInstance("RSA"); */
                void run() {}
            }
            "#,
        );
        assert!(unit.facts().is_empty());
    }

    #[test]
    fn records_scopes_imports_and_literals() {
        let unit = lower(
            r#"
            import org.bouncycastle.pqc.crypto.mlkem.*;
            class Outer {
                class Inner {
                    String alg() { return "ML-KEM-768"; }
                }
            }
            "#,
        );
        insta::assert_yaml_snapshot!(unit);
    }

    #[test]
    fn columns_count_code_points() {
        let unit =
            lower("class A { String s = \"ñ\"; void m() { /*ñ*/ Cipher.getInstance(\"RSA\"); } }");
        let call = unit
            .facts()
            .iter()
            .find(|f| matches!(f.kind, FactKind::Call { .. }))
            .unwrap();
        let prefix = "class A { String s = \"ñ\"; void m() { /*ñ*/ ";
        assert_eq!(
            call.location.start.column as usize,
            prefix.chars().count() + 1
        );
        assert_eq!(call.location.start_byte, prefix.len());
    }

    #[test]
    fn decodes_escapes() {
        assert_eq!(string_value(r#""a\"b\\cA""#).as_deref(), Some("a\"b\\cA"));
        assert_eq!(int_value("0x80"), Some(128));
        assert_eq!(int_value("1_024L"), Some(1024));
    }

    fn fields(unit: &SourceUnit) -> Vec<(TypeRef, String)> {
        unit.facts()
            .iter()
            .filter_map(|f| match &f.kind {
                FactKind::Field { owner, name } => Some((owner.clone(), name.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn records_static_field_reads() {
        let unit = lower(
            r#"
            import com.nimbusds.jose.JWSAlgorithm;
            import io.jsonwebtoken.Jwts;
            class A {
                void run() {
                    sign(JWSAlgorithm.RS256);
                    Jwts.SIG.ES256.keyPair().build();
                    sign(com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256);
                }
            }
            "#,
        );
        assert_eq!(
            fields(&unit),
            [
                (
                    TypeRef::qualified("com.nimbusds.jose.JWSAlgorithm"),
                    "RS256".into()
                ),
                (
                    TypeRef::qualified("io.jsonwebtoken.Jwts.SIG"),
                    "ES256".into()
                ),
                (
                    TypeRef::qualified("com.nimbusds.jose.JWEAlgorithm"),
                    "RSA_OAEP_256".into()
                ),
            ]
        );
    }

    #[test]
    fn instance_fields_are_not_static_reads() {
        let unit = lower(
            r#"
            class A {
                Config config;
                void run(Options options) {
                    use(this.alg, config.alg, options.Alg, config.inner.Alg);
                }
            }
            "#,
        );
        assert!(fields(&unit).is_empty(), "{:?}", fields(&unit));
    }

    #[test]
    fn resolves_static_imports() {
        let unit = lower(
            r#"
            import static com.nimbusds.jose.JWSAlgorithm.RS256;
            import static com.auth0.jwt.algorithms.Algorithm.RSA256;
            class A {
                void run(Object pub, Object priv) {
                    sign(RS256);
                    RSA256(pub, priv);
                }
                void shadowed() {
                    String RS256 = "local";
                    use(RS256);
                }
            }
            "#,
        );
        assert_eq!(
            fields(&unit),
            [(
                TypeRef::qualified("com.nimbusds.jose.JWSAlgorithm"),
                "RS256".into()
            )]
        );
        let algorithm = TypeRef::qualified("com.auth0.jwt.algorithms.Algorithm");
        assert!(
            calls(&unit)
                .iter()
                .any(|(r, m, _)| m == "RSA256" && r.as_ref() == Some(&algorithm))
        );
    }

    #[test]
    fn local_methods_shadow_static_imports() {
        let unit = lower(
            r#"
            import static com.auth0.jwt.algorithms.Algorithm.RSA256;
            class A {
                void run() { RSA256(); }
                void RSA256() {}
            }
            "#,
        );
        assert_eq!(calls(&unit)[0].0, None);
    }
}
