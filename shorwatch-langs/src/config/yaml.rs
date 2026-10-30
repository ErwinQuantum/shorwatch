//! YAML, through tree-sitter-yaml.

use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, SourceUnit};
use tree_sitter::{Node, Parser};

use crate::span::Lines;
use crate::{Frontend, LangError};

#[derive(Debug, Clone, Copy, Default)]
pub struct YamlFrontend;

impl Frontend for YamlFrontend {
    fn language(&self) -> Language {
        Language::Yaml
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["yml", "yaml"]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_yaml::LANGUAGE.into())
            .map_err(|e| LangError::Grammar(Language::Yaml, e.to_string()))?;
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| LangError::Parse(path.to_owned()))?;
        crate::depth::check(path, tree.root_node())?;
        let mut lowering = YamlLowering {
            src: source,
            lines: Lines::new(source),
            unit: SourceUnit::new(path, Language::Yaml),
        };
        lowering.walk(tree.root_node(), String::new());
        Ok(lowering.unit)
    }
}

struct YamlLowering<'s> {
    src: &'s str,
    lines: Lines<'s>,
    unit: SourceUnit,
}

impl YamlLowering<'_> {
    /// Configuration files nest a handful of levels, so plain recursion is fine.
    fn walk(&mut self, node: Node<'_>, prefix: String) {
        match node.kind() {
            "block_mapping" | "flow_mapping" => {
                let mut cursor = node.walk();
                let pairs: Vec<_> = node.named_children(&mut cursor).collect();
                for pair in pairs {
                    let key = pair.child_by_field_name("key").and_then(|k| self.scalar(k));
                    if let (Some(key), Some(value)) = (key, pair.child_by_field_name("value")) {
                        self.walk(value, join(&prefix, &key));
                    }
                }
            }
            "block_sequence" | "flow_sequence" => {
                let mut cursor = node.walk();
                let items: Vec<_> = node
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .collect();
                for (i, item) in items.into_iter().enumerate() {
                    self.walk(item, format!("{prefix}[{i}]"));
                }
            }
            "plain_scalar" | "double_quote_scalar" | "single_quote_scalar" | "block_scalar" => {
                if let Some(value) = self.scalar(node) {
                    let location = self.lines.range(node.start_byte(), node.end_byte());
                    let kind = FactKind::Property { key: prefix, value };
                    self.unit.push(kind, SourceUnit::ROOT, location);
                }
            }
            // Each document of a stream starts again from the root.
            "document" | "stream" => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                for child in children {
                    self.walk(child, String::new());
                }
            }
            // Wrappers (block/flow nodes, sequence items, anchors, tags).
            _ => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                for child in children {
                    self.walk(child, prefix.clone());
                }
            }
        }
    }

    /// The text of a scalar node (or of the scalar inside a wrapper), unquoted.
    fn scalar(&self, node: Node<'_>) -> Option<String> {
        let text = &self.src[node.byte_range()];
        match node.kind() {
            "plain_scalar" => Some(text.trim().to_owned()),
            "single_quote_scalar" => Some(text[1..text.len() - 1].replace("''", "'")),
            "double_quote_scalar" => Some(text[1..text.len() - 1].replace("\\\"", "\"")),
            "block_scalar" => text
                .split_once('\n')
                .map(|(_, body)| body.trim().to_owned()),
            "comment" | "anchor" | "tag" | "alias" => None,
            _ => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                children.into_iter().find_map(|c| self.scalar(c))
            }
        }
    }
}

fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}
