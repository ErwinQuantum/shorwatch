//! Everything the built-in rules detect, grouped by algorithm. Reorganizing
//! rule files must leave this snapshot unchanged; a diff here is a real change
//! in coverage and deserves review.

use std::collections::BTreeMap;

#[test]
fn pattern_inventory() {
    let mut inventory: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rule in shorwatch_rules::builtin_rules().unwrap() {
        let patterns = inventory.entry(rule.algorithm.clone()).or_default();
        for pattern in &rule.patterns {
            patterns.push(format!("{pattern:?}"));
        }
    }
    for patterns in inventory.values_mut() {
        patterns.sort();
    }
    insta::assert_yaml_snapshot!(inventory);
}
