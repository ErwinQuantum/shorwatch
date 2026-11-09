//! Terminal report snapshots, with colours stripped for readability.

use super::*;
use crate::fixtures::scan;

fn plain(text: &str) -> String {
    anstream::adapter::strip_str(text).to_string()
}

fn view(view: View) -> Options {
    Options {
        view,
        ..Options::default()
    }
}

#[test]
fn summary_report() {
    let options = Options {
        report: Some("file:///tmp/shorwatch/payments.html".into()),
        ..Options::default()
    };
    insta::assert_snapshot!(plain(&render(&scan(), &options)));
}

#[test]
fn overview_report() {
    insta::assert_snapshot!(plain(&render(&scan(), &view(View::Overview))));
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
    insta::assert_snapshot!(plain(&render(&scan, &view(View::Overview))));
}

#[test]
fn detailed_report() {
    insta::assert_snapshot!(plain(&render(&scan(), &view(View::Details))));
}

#[test]
fn compact_report() {
    insta::assert_snapshot!(plain(&render(&scan(), &view(View::Compact))));
}

#[test]
fn clean_report() {
    let clean = crate::Scan {
        files_scanned: 7,
        ..Default::default()
    };
    assert_eq!(
        plain(&render(&clean, &Options::default())),
        "\n Summary  no quantum-vulnerable cryptography found in 7 files\n"
    );
}

#[test]
fn the_summary_counts_the_libraries_and_names_the_old_ones() {
    let mut scan = scan();
    scan.dependencies = crate::fixtures::dependencies();
    let text = plain(&render(&scan, &Options::default()));
    assert!(
        text.contains(
            "4 cryptographic libraries in the build files · 2 before post-quantum support (BouncyCastle 1.70)"
        ),
        "{text}"
    );
}

#[test]
fn a_clean_scan_still_says_which_libraries_it_saw() {
    let clean = crate::Scan {
        files_scanned: 7,
        dependencies: crate::fixtures::dependencies()[1..2].to_vec(),
        ..Default::default()
    };
    assert_eq!(
        plain(&render(&clean, &Options::default())),
        "\n Summary  no quantum-vulnerable cryptography found in 7 files\n          1 cryptographic library in the build files\n"
    );
}

#[test]
fn report_is_coloured_before_stripping() {
    assert!(render(&scan(), &Options::default()).contains("\x1b["));
}

#[test]
fn verdict_says_why_the_scan_fails() {
    assert_eq!(
        plain(&verdict(2, Some("https://ci.example/run/7"))),
        "\n ✖ 2 findings fail the scan (exit code 1) · see --fail-on, --fail-severity\n   Report https://ci.example/run/7\n"
    );
}

fn language(language: &str, files: usize) -> crate::LanguageFiles {
    crate::LanguageFiles {
        language: language.into(),
        files,
    }
}

#[test]
fn a_scan_says_which_languages_it_analyzed() {
    let scan = Scan {
        languages: vec![language("Java", 120), language("C#", 12)],
        ..crate::fixtures::scan()
    };
    let out = summary(&scan);
    assert!(out.contains("analyzed: 120 Java · 12 C#"), "{out}");
    assert!(!out.contains("NOT analyzed"), "{out}");
}

#[test]
fn skipped_languages_are_called_out_even_when_nothing_was_found() {
    let scan = Scan {
        findings: Vec::new(),
        languages: vec![language("YAML", 2)],
        unanalyzed: vec![language("Python", 340), language("Go", 80)],
        ..crate::fixtures::scan()
    };
    let out = summary(&scan);
    assert!(
        out.contains("no quantum-vulnerable cryptography found"),
        "{out}"
    );
    assert!(
        out.contains("NOT analyzed: 340 Python · 80 Go (no frontend for them yet)"),
        "{out}"
    );
}
