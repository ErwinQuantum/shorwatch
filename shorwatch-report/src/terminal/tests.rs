//! Terminal report snapshots, with colours stripped for readability.

use super::*;
use crate::fixtures::scan;

fn plain(text: &str) -> String {
    anstream::adapter::strip_str(text).to_string()
}

#[test]
fn detailed_report() {
    insta::assert_snapshot!(plain(&render(&scan(), Options::default())));
}

#[test]
fn compact_report() {
    insta::assert_snapshot!(plain(&render(&scan(), Options { compact: true })));
}

#[test]
fn clean_report() {
    let clean = crate::Scan {
        files_scanned: 7,
        ..Default::default()
    };
    assert_eq!(
        plain(&render(&clean, Options::default())),
        "\n Summary  no quantum-vulnerable cryptography found in 7 files\n"
    );
}

#[test]
fn report_is_coloured_before_stripping() {
    assert!(render(&scan(), Options::default()).contains("\x1b["));
}
