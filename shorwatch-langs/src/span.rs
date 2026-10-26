//! Locations of tree-sitter nodes.

use shorwatch_core::ir::{Location, Position};
use tree_sitter::{Node, Point};

pub(crate) fn location(src: &str, node: Node<'_>) -> Location {
    Location {
        start: position(src, node.start_byte(), node.start_position()),
        end: position(src, node.end_byte(), node.end_position()),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

/// tree-sitter columns are byte offsets; SARIF wants code points.
fn position(src: &str, byte: usize, point: Point) -> Position {
    let line_start = byte - point.column;
    let column = src
        .get(line_start..byte)
        .map_or(point.column, |s| s.chars().count());
    Position {
        line: u32::try_from(point.row + 1).unwrap_or(u32::MAX),
        column: u32::try_from(column + 1).unwrap_or(u32::MAX),
    }
}
