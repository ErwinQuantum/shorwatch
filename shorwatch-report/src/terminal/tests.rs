//! Terminal report snapshots, with colours stripped for readability.

use super::*;
use crate::fixtures::scan;

fn plain(text: &str) -> String {
    anstream::adapter::strip_str(text).to_string()
}

fn view(view: View) -> Options {
    Options { view }
}

#[test]
fn overview_report() {
    insta::assert_snapshot!(plain(&render(&scan(), Options::default())));
}

/// Several projects: one group each, the clean ones listed too.
#[test]
fn overview_of_several_projects() {
    let mut scan = scan();
    scan.projects = vec![
        crate::Project {
            name: "auth".into(),
            root: "src/main".into(),
            files_scanned: 8,
        },
        crate::Project {
            name: "auth-tests".into(),
            root: "src/test".into(),
            files_scanned: 3,
        },
        crate::Project {
            name: "billing".into(),
            root: "billing".into(),
            files_scanned: 5,
        },
    ];
    insta::assert_snapshot!(plain(&render(&scan, Options::default())));
}

#[test]
fn detailed_report() {
    insta::assert_snapshot!(plain(&render(&scan(), view(View::Details))));
}

#[test]
fn compact_report() {
    insta::assert_snapshot!(plain(&render(&scan(), view(View::Compact))));
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
