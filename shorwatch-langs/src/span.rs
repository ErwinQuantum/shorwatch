//! Locations of tree-sitter nodes and of byte ranges in text.

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

/// Location of `start..end`, with columns in code points like the Java frontend.
pub(crate) fn byte_range(src: &str, start: usize, end: usize) -> Location {
    Location {
        start: text_position(src, start),
        end: text_position(src, end),
        start_byte: start,
        end_byte: end,
    }
}

fn text_position(src: &str, byte: usize) -> Position {
    let before = &src[..byte];
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    Position {
        line: u32::try_from(before.matches('\n').count() + 1).unwrap_or(u32::MAX),
        column: u32::try_from(src[line_start..byte].chars().count() + 1).unwrap_or(u32::MAX),
    }
}
