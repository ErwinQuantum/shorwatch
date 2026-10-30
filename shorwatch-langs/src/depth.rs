//! A bound on how deeply a syntax tree may nest.
//!
//! Real code nests a few dozen levels (a long `a + b + c...` concatenation, a
//! generated table, one level per operand). A hostile file can nest hundreds
//! of thousands within the size limit, and every pass over the tree after
//! parsing would recurse that far.

use tree_sitter::Node;

use crate::LangError;

/// Deeper than any source file a person or a generator writes in practice.
pub(crate) const MAX_DEPTH: usize = 2_500;

/// How many ancestors a literal looks through for the calls it is an argument
/// of. Asking a node for its parent costs its depth, so an unbounded climb is
/// cubic over a long concatenation; a call this far up is not this literal's.
pub(crate) const MAX_ENCLOSING: usize = 64;

/// Fails when `root` nests deeper than [`MAX_DEPTH`]. Walks the tree with a
/// cursor, so checking it never recurses.
pub(crate) fn check(path: &str, root: Node<'_>) -> Result<(), LangError> {
    let mut cursor = root.walk();
    let mut depth = 0;
    loop {
        if cursor.goto_first_child() {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(LangError::TooDeep(path.to_owned(), MAX_DEPTH));
            }
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return Ok(());
            }
            depth -= 1;
        }
    }
}
