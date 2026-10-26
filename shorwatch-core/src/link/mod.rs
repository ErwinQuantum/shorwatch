//! Cross-file resolution.
//!
//! Frontends lower each file in isolation. [`link`] connects what only makes
//! sense across files: values injected from configuration
//! (`@Value("${jwt.algorithm}")`) and the config entries that define them.

use crate::ir::SourceUnit;

mod config;

/// Resolves, in every unit, what depends on other units: injected values
/// (see [`config`]).
pub fn link(units: &mut [SourceUnit]) {
    config::inject(units);
}

#[cfg(test)]
mod tests;
