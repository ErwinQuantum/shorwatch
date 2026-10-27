//! Suppression tests, on findings the real frontends and rules produce.

use shorwatch_core::analyze;
use shorwatch_report::{Scan, Suppression};

use super::{Baseline, apply};
use crate::args::RuleSource;

fn scan_of(files: &[(&str, &str)]) -> Scan {
    let rules = crate::rules::load(&RuleSource { dirs: Vec::new() }).unwrap();
    let mut scan = Scan::default();
    for (path, source) in files {
        let extension = path.rsplit('.').next().unwrap();
        let frontend = shorwatch_langs::for_extension(extension).unwrap();
        let (unit, text) = frontend
            .lower_bytes(path, source.as_bytes().to_vec())
            .unwrap();
        scan.findings.extend(analyze(&unit, &rules));
        scan.sources.insert((*path).to_owned(), text.unwrap());
    }
    scan
}

fn java(body: &str) -> String {
    format!(
        "import java.security.*;\nclass Keys {{\n  void k() throws Exception {{\n{body}\n  }}\n}}\n"
    )
}

fn reasons(scan: &Scan) -> Vec<Option<&str>> {
    scan.suppressed
        .iter()
        .map(|s| match &s.suppression {
            Suppression::InSource { justification } => justification.as_deref(),
            Suppression::Baseline => Some("<baseline>"),
        })
        .collect()
}

#[test]
fn a_comment_on_the_line_ignores_the_rules_it_names() {
    let source = java(
        r#"    KeyPairGenerator.getInstance("RSA"); // shorwatch:ignore jvm.jca.rsa -- partner API, until Q3
    MessageDigest.getInstance("SHA-1"); // shorwatch:ignore jvm.jca.rsa"#,
    );
    let mut scan = scan_of(&[("Keys.java", &source)]);
    apply(&mut scan, None);
    assert_eq!(reasons(&scan), [Some("partner API, until Q3")]);
    let left: Vec<_> = scan.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(left, ["jvm.jca.sha1"], "the comment names another rule");
}

#[test]
fn a_comment_alone_above_covers_the_next_line_and_profiles_name_rules() {
    let source = java(
        r#"    // shorwatch:ignore rsa -- legacy clients
    KeyPairGenerator.getInstance("RSA");
    KeyPairGenerator.getInstance("RSA");"#,
    );
    let mut scan = scan_of(&[("Keys.java", &source)]);
    apply(&mut scan, None);
    assert_eq!(reasons(&scan), [Some("legacy clients")]);
    assert_eq!(scan.findings.len(), 1, "only the line right below");
}

#[test]
fn yaml_comments_work_the_same_way() {
    let yaml = "spring:\n  security:\n    oauth2:\n      resourceserver:\n        jwt:\n          jws-algorithms: RS256 # shorwatch:ignore\n";
    let mut scan = scan_of(&[("application.yml", yaml)]);
    assert!(!scan.findings.is_empty());
    apply(&mut scan, None);
    assert!(scan.findings.is_empty());
    assert_eq!(reasons(&scan), [None]);
}

#[test]
fn similar_words_are_not_the_marker() {
    let source = java(
        r#"    KeyPairGenerator.getInstance("RSA"); // shorwatch:ignored
    KeyPairGenerator.getInstance("DSA"); // see the shorwatch docs"#,
    );
    let mut scan = scan_of(&[("Keys.java", &source)]);
    apply(&mut scan, None);
    assert!(scan.suppressed.is_empty());
}

#[test]
fn the_baseline_knows_findings_after_the_lines_above_them_change() {
    let before = java(r#"    KeyPairGenerator.getInstance("RSA");"#);
    let recorded = scan_of(&[("Keys.java", &before)]);
    let baseline = Baseline::of(&recorded);
    assert_eq!(baseline.len(), 1);

    // Two lines added above, re-indented, and a new finding.
    let after = java(
        r#"
    int unrelated = 0;
        KeyPairGenerator.getInstance("RSA");
    KeyPairGenerator.getInstance("DSA");"#,
    );
    let mut scan = scan_of(&[("Keys.java", &after)]);
    apply(&mut scan, Some(&baseline));
    assert_eq!(reasons(&scan), [Some("<baseline>")]);
    let new: Vec<_> = scan.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(new, ["jvm.jca.dsa"]);
}

#[test]
fn a_second_identical_line_is_a_new_finding() {
    let line = r#"    KeyPairGenerator.getInstance("RSA");"#;
    let baseline = Baseline::of(&scan_of(&[("Keys.java", &java(line))]));
    let mut scan = scan_of(&[("Keys.java", &java(&format!("{line}\n{line}")))]);
    apply(&mut scan, Some(&baseline));
    assert_eq!(scan.suppressed.len(), 1);
    assert_eq!(scan.findings.len(), 1);
}

#[test]
fn baselines_round_trip_and_reject_other_versions() {
    let baseline = Baseline::of(&scan_of(&[(
        "Keys.java",
        &java(r#"    KeyPairGenerator.getInstance("RSA");"#),
    )]));
    let dir = std::env::temp_dir().join(format!("shorwatch-baseline-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("baseline.json");
    std::fs::write(&file, baseline.to_json()).unwrap();
    assert_eq!(Baseline::load(&file).unwrap().len(), 1);

    std::fs::write(
        &file,
        baseline
            .to_json()
            .replace("\"version\": 1", "\"version\": 9"),
    )
    .unwrap();
    let error = Baseline::load(&file).unwrap_err().to_string();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(error.contains("version 9"), "{error}");
}
