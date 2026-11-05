//! Coverage of the names the JDK and BouncyCastle accept.
//!
//! `tests/jdk/names.tsv` lists every algorithm and alias the JDK 21 providers
//! register, and `tests/jdk/bouncycastle.tsv` the ones BouncyCastle 1.85
//! registers, for the types Shorwatch reads (`Signature`, `KeyPairGenerator`,
//! `Cipher`...), with the profiles each name must produce (`-` for none).
//! Aliases and OIDs are valid algorithm names (`Signature.getInstance(
//! "1.2.840.113549.1.1.11")` is `SHA256withRSA`), and a rule that misses one is a
//! silent false negative. Most gaps found by hand were of this kind, so the
//! test calls every name through its factory and compares, per call, the
//! profiles reported with the ones expected.
//!
//! A provider that adds a name does not change this file: add the row when you
//! update its table, and the test says what the rules do with it.

use std::collections::BTreeSet;
use std::fmt::Write;

use shorwatch_core::{Library, RuleSet, analyze, link};

/// The factory class each `names.tsv` type is created through.
const FACTORIES: &[(&str, &str)] = &[
    (
        "AlgorithmParameterGenerator",
        "java.security.AlgorithmParameterGenerator",
    ),
    ("AlgorithmParameters", "java.security.AlgorithmParameters"),
    ("Cipher", "javax.crypto.Cipher"),
    ("KEM", "javax.crypto.KEM"),
    ("KeyAgreement", "javax.crypto.KeyAgreement"),
    ("KeyFactory", "java.security.KeyFactory"),
    ("KeyGenerator", "javax.crypto.KeyGenerator"),
    ("KeyPairGenerator", "java.security.KeyPairGenerator"),
    ("Mac", "javax.crypto.Mac"),
    ("MessageDigest", "java.security.MessageDigest"),
    ("SecretKeyFactory", "javax.crypto.SecretKeyFactory"),
    ("Signature", "java.security.Signature"),
];

struct Row {
    kind: String,
    name: String,
    canonical: String,
    expected: BTreeSet<String>,
}

fn rows(table: &str) -> Vec<Row> {
    table
        .lines()
        .map(|line| {
            let c: Vec<_> = line.split('\t').collect();
            assert_eq!(c.len(), 4, "malformed row: {line}");
            Row {
                kind: c[0].into(),
                name: c[1].into(),
                canonical: c[2].into(),
                expected: c[3]
                    .split(',')
                    .filter(|p| *p != "-")
                    .map(String::from)
                    .collect(),
            }
        })
        .collect()
}

#[test]
fn every_name_the_jdk_accepts_is_read() {
    check("JDK", include_str!("jdk/names.tsv"));
}

#[test]
fn every_name_bouncycastle_accepts_is_read() {
    check("BouncyCastle", include_str!("jdk/bouncycastle.tsv"));
}

fn check(provider: &str, table: &str) {
    let rows = rows(table);
    // One call per line, so a finding's line says which name it belongs to.
    let mut source = String::from("class Probe {\n  void probe() throws Exception {\n");
    for row in &rows {
        let factory = FACTORIES
            .iter()
            .find(|(kind, _)| *kind == row.kind)
            .unwrap_or_else(|| panic!("no factory for {}", row.kind))
            .1;
        let _ = writeln!(source, "    {factory}.getInstance(\"{}\");", row.name);
    }
    source.push_str("  }\n}\n");

    let frontend = shorwatch_langs::for_extension("java").unwrap();
    let (unit, _) = frontend
        .lower_bytes("Probe.java", source.into_bytes())
        .unwrap();
    let mut units = vec![unit];
    link(&mut units, &Library::default());
    let rules: RuleSet = shorwatch_rules::builtin().unwrap();

    let mut reported = vec![BTreeSet::new(); rows.len()];
    for finding in analyze(&units[0], &rules) {
        // Line 1 is the class, line 2 the method: the first call is line 3.
        let profile = finding.rule_id.rsplit('.').next().unwrap().to_string();
        reported[finding.location.start.line as usize - 3].insert(profile);
    }

    let wrong: Vec<String> = rows
        .iter()
        .zip(&reported)
        .filter(|(row, got)| &row.expected != *got)
        .map(|(row, got)| {
            format!(
                "{}.getInstance(\"{}\") [{}]: expected {:?}, got {:?}",
                row.kind, row.name, row.canonical, row.expected, got
            )
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {} {provider} names are read differently than expected:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
}
