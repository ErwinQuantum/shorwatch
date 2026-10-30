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

/// Where the lines of a text start, to turn byte ranges into locations with
/// columns in code points like the Java frontend. Built once per file: finding
/// the line by counting from the top for every fact is quadratic.
pub(crate) struct Lines<'s> {
    src: &'s str,
    starts: Vec<usize>,
}

impl<'s> Lines<'s> {
    pub(crate) fn new(src: &'s str) -> Self {
        let newlines = src.bytes().enumerate().filter(|&(_, b)| b == b'\n');
        let starts = std::iter::once(0)
            .chain(newlines.map(|(i, _)| i + 1))
            .collect();
        Self { src, starts }
    }

    pub(crate) fn range(&self, start: usize, end: usize) -> Location {
        Location {
            start: self.position(start),
            end: self.position(end),
            start_byte: start,
            end_byte: end,
        }
    }

    fn position(&self, byte: usize) -> Position {
        let line = self.starts.partition_point(|&start| start <= byte) - 1;
        let column = self.src[self.starts[line]..byte].chars().count();
        Position {
            line: u32::try_from(line + 1).unwrap_or(u32::MAX),
            column: u32::try_from(column + 1).unwrap_or(u32::MAX),
        }
    }
}
