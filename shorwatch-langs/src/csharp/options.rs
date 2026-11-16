//! The options pattern: a settable class bound to a section of the
//! configuration, which the rest of the code reads through `IOptions<T>`.
//!
//! - `services.Configure<JwtOptions>(config.GetSection("Jwt"))`
//! - `config.GetSection("Jwt").Get<JwtOptions>()`
//! - `config.GetSection("Jwt").Bind(instance)`
//! - `services.AddOptions<JwtOptions>().Bind(config.GetSection("Jwt"))`
//! - `services.AddOptions<JwtOptions>().BindConfiguration("Jwt")`
//!
//! Each is a [`FactKind::Bind`](shorwatch_core::ir::FactKind::Bind): the type
//! and the section. The class that declares the options is usually another
//! file, so what its properties hold is for `link` to settle
//! ([`ArgValue::Bound`](shorwatch_core::ir::ArgValue::Bound)). The section
//! name may be a constant of that class (`JwtOptions.SectionName`), which is
//! why it stays an argument and not a string.
//!
//! Not followed: a lambda (`Configure<T>(o => config.Bind(o))`), whose
//! parameter has no written type, and sections named by anything but a
//! literal or a constant.

use tree_sitter::Node;

use super::configuration::text_of;
use super::syntax::{generic_args, type_name};
use super::{Lowering, invoked};
use crate::managed::{ArgSource, Pending, PendingArg};
use shorwatch_core::ir::{ArgValue, ScopeId};

/// A section path is a handful of nested `GetSection` calls.
const MAX_SECTIONS: usize = 8;

/// The configuration a binding reads: where it lives and the section.
struct Section<'t> {
    base: Node<'t>,
    prefix: PendingArg,
}

impl Lowering<'_> {
    /// Records the binding `call` makes, if it makes one.
    pub(super) fn options_binding(&mut self, call: Node<'_>, scope: ScopeId) {
        let Some((object, method)) = invoked(call, self.src) else {
            return;
        };
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let arguments = self.argument_nodes(call);
        let generic = generic_args(function, self.src)
            .first()
            .map(|ty| type_name(ty));
        let found = match (method, arguments.as_slice()) {
            // `Configure<T>(section)`, `Configure<T>(name, section)`.
            ("Configure", [.., section]) => generic.zip(self.section(*section)),
            // `section.Get<T>()`.
            ("Get", []) => generic.zip(object.and_then(|o| self.section(o))),
            // `section.Bind(instance)`, or `AddOptions<T>().Bind(section)`.
            ("Bind", [argument]) => match object.and_then(|o| self.section(o)) {
                Some(section) => self.instance_type(*argument, scope).zip(Some(section)),
                None => object
                    .and_then(|o| self.added_options(o))
                    .zip(self.section(*argument)),
            },
            // `AddOptions<T>().BindConfiguration("Jwt")`: the string is the
            // section, and no configuration object is written.
            ("BindConfiguration", [path]) => object.and_then(|o| self.added_options(o)).map(|ty| {
                let prefix = self.pending(*path);
                (
                    ty,
                    Section {
                        base: *path,
                        prefix,
                    },
                )
            }),
            _ => None,
        };
        let Some((ty, section)) = found else {
            return;
        };
        let receiver = if method == "BindConfiguration" {
            None
        } else {
            match self.receiver(section.base, 0) {
                Some(receiver) => Some(receiver),
                None => return,
            }
        };
        self.defer(
            Pending::Bind {
                ty,
                receiver,
                prefix: section.prefix,
            },
            scope,
            call,
        );
    }

    /// `T` of `x.AddOptions<T>(..)`.
    fn added_options(&self, node: Node<'_>) -> Option<String> {
        if node.kind() != "invocation_expression" {
            return None;
        }
        let (_, method) = invoked(node, self.src)?;
        if method != "AddOptions" {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        generic_args(function, self.src)
            .first()
            .map(|ty| type_name(ty))
    }

    /// The type of the object `Bind` fills: a variable of a written (or
    /// obvious) type, or a construction.
    fn instance_type(&self, node: Node<'_>, scope: ScopeId) -> Option<String> {
        match node.kind() {
            "identifier" => self.file.lookup(scope, self.text(node))?.ty.clone(),
            "object_creation_expression" => node
                .child_by_field_name("type")
                .map(|ty| type_name(self.text(ty))),
            _ => None,
        }
    }

    /// `c.GetSection("A").GetSection("B")` as the configuration `c` and the
    /// path `A:B`; with one section, whatever names it (`JwtOptions.Section`).
    fn section<'t>(&self, mut node: Node<'t>) -> Option<Section<'t>> {
        let mut parts: Vec<PendingArg> = Vec::new();
        for _ in 0..MAX_SECTIONS {
            if node.kind() != "invocation_expression" {
                break;
            }
            let Some((Some(object), method)) = invoked(node, self.src) else {
                break;
            };
            if !matches!(method, "GetSection" | "GetRequiredSection") {
                break;
            }
            let mut arguments = self.args(node);
            if arguments.len() != 1 {
                break;
            }
            parts.extend(arguments.pop());
            node = object;
        }
        parts.reverse();
        let prefix = match parts.len() {
            0 => return None,
            1 => parts.pop()?,
            _ => {
                let names: Option<Vec<String>> = parts.iter().map(text_of).collect();
                let joined = names?.join(":");
                PendingArg {
                    raw: joined.clone(),
                    location: parts[0].location,
                    source: ArgSource::Value(ArgValue::Str(joined)),
                }
            }
        };
        Some(Section { base: node, prefix })
    }

    /// The expression of each argument of a call.
    fn argument_nodes<'t>(&self, call: Node<'t>) -> Vec<Node<'t>> {
        let Some(list) = call.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut cursor = list.walk();
        list.named_children(&mut cursor)
            .filter(|a| a.kind() == "argument")
            .filter_map(super::argument_value)
            .collect()
    }
}
