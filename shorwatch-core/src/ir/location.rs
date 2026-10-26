//! Positions and ranges in a source file.

use serde::Serialize;

/// A point in the source. Both fields are 1-based; `column` counts Unicode
/// code points, which is what SARIF's `unicodeCodePoints` column kind expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

/// A source range, as positions for humans and byte offsets for edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Location {
    pub start: Position,
    pub end: Position,
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Location {
    /// Convenience constructor for single-line ranges, mostly useful in tests.
    pub fn line(line: u32, start_column: u32, end_column: u32) -> Self {
        Self {
            start: Position {
                line,
                column: start_column,
            },
            end: Position {
                line,
                column: end_column,
            },
            start_byte: 0,
            end_byte: 0,
        }
    }
}
