//! Reads of .NET configuration (`Microsoft.Extensions.Configuration`): values
//! that come from `appsettings.json`, an environment or a vault, never from
//! the code.
//!
//! - `config["Jwt:Algorithm"]`
//! - `config.GetValue<string>("Jwt:Algorithm", "RS256")`
//! - `config.GetSection("Jwt")["Algorithm"]`, `config.GetSection("Jwt").GetValue<string>("Algorithm")`
//! - `config.GetSection("Jwt:Algorithm").Value`
//!
//! Which receivers are configurations is not known here (phase one has no
//! types): [`ArgSource::Config`] keeps the receiver and phase two decides.

use tree_sitter::Node;

use super::{Lowering, argument_value, invoked, simple_name};
use crate::managed::{ArgSource, PendingArg};
use shorwatch_core::ir::ArgValue;

/// A section path is a handful of nested `GetSection` calls.
const MAX_SECTIONS: usize = 8;

impl Lowering<'_> {
    /// The configuration read `node` is, if it is one.
    pub(super) fn configuration(&self, node: Node<'_>) -> Option<ArgSource> {
        let (object, key, default) = match node.kind() {
            "element_access_expression" => {
                let list = node.child_by_field_name("subscript")?;
                let mut cursor = list.walk();
                let mut arguments = list
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() == "argument");
                let key = self.string_of(argument_value(arguments.next()?)?)?;
                if arguments.next().is_some() {
                    return None;
                }
                (node.child_by_field_name("expression")?, key, None)
            }
            "invocation_expression" => {
                let (object, method) = invoked(node, self.src)?;
                if method != "GetValue" {
                    return None;
                }
                let mut args = self.args(node).into_iter();
                let key = text_of(&args.next()?)?;
                let default = args.next().as_ref().and_then(text_of);
                (object?, key, default)
            }
            // `GetSection("Jwt:Algorithm").Value`
            "member_access_expression" => {
                let name = simple_name(node.child_by_field_name("name")?, self.src)?;
                if name != "Value" {
                    return None;
                }
                let (base, path) = self.sections(node.child_by_field_name("expression")?);
                if path.is_empty() {
                    return None;
                }
                return Some(ArgSource::Config {
                    receiver: self.receiver(base, 0)?,
                    key: path.join(":"),
                    default: None,
                });
            }
            _ => return None,
        };
        let (base, mut path) = self.sections(object);
        path.push(key);
        Some(ArgSource::Config {
            receiver: self.receiver(base, 0)?,
            key: path.join(":"),
            default,
        })
    }

    /// `c.GetSection("A").GetSection("B")` is the configuration `c` and the
    /// path `A`, `B`.
    fn sections<'t>(&self, mut node: Node<'t>) -> (Node<'t>, Vec<String>) {
        let mut path = Vec::new();
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
            let args = self.args(node);
            let [section] = args.as_slice() else { break };
            let Some(section) = text_of(section) else {
                break;
            };
            path.push(section);
            node = object;
        }
        path.reverse();
        (node, path)
    }

    fn string_of(&self, node: Node<'_>) -> Option<String> {
        match self.literal(node)? {
            ArgValue::Str(text) => Some(text),
            _ => None,
        }
    }
}

/// The text of an argument that is a string literal.
fn text_of(arg: &PendingArg) -> Option<String> {
    match &arg.source {
        ArgSource::Value(ArgValue::Str(text)) => Some(text.clone()),
        _ => None,
    }
}
