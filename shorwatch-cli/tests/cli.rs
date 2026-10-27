//! End-to-end tests: run the real `shorwatch` binary on the rule fixtures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures(folder: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../shorwatch-rules/tests/fixtures")
        .join(folder)
}

fn shorwatch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_shorwatch"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn path(folder: &str) -> String {
    fixtures(folder).display().to_string()
}

#[test]
fn vulnerable_project_exits_with_1_and_reports_locations() {
    let output = shorwatch(&["scan", &path("spring-app")]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("jvm.jca.rsa"), "{text}");
    assert!(
        text.contains("AuthorizationServerConfig.java:40:49"),
        "{text}"
    );
    // Java sources and their Kotlin twins.
    assert!(text.contains("WebhookSigner.kt:19:9"), "{text}");
    assert!(text.contains("14 findings in 10 files"), "{text}");
    assert!(!text.contains('\x1b'), "piped output must not be coloured");
}

#[test]
fn clean_files_exit_with_0() {
    let output = shorwatch(&["scan", &path("dh/Clean.java")]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("no quantum-vulnerable cryptography found in 1 file"));
}

#[test]
fn fail_on_controls_the_exit_code() {
    let never = shorwatch(&["scan", &path("spring-app"), "--fail-on", "never"]);
    assert_eq!(never.status.code(), Some(0));

    // Only in-transition findings: fine for `vulnerable`, a failure for `any`.
    let hybrid = path("ecdh/Hybrid.java");
    assert_eq!(shorwatch(&["scan", &hybrid]).status.code(), Some(0));
    let any = shorwatch(&["scan", &hybrid, "--fail-on", "any"]);
    assert_eq!(any.status.code(), Some(1));
}

#[test]
fn sarif_output_is_valid_and_uses_relative_uris() {
    let output = shorwatch(&["scan", &path("spring-injected"), "--format", "sarif"]);
    let log: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(log["version"], "2.1.0");
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for result in results {
        let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.contains('\\') && !uri.contains(':'), "{uri}");
    }
}

#[test]
fn injected_config_values_are_resolved_across_files() {
    let output = shorwatch(&["scan", &path("spring-injected"), "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let rules: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        rules.contains(&"jvm.nimbus.jose-rsa".to_owned()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"config.app.jose-rsa".to_owned()),
        "{rules:?}"
    );
}

#[test]
fn min_severity_filters_findings() {
    let output = shorwatch(&[
        "scan",
        &path("spring-app"),
        "--min-severity",
        "high",
        "--format",
        "json",
    ]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    for finding in report["findings"].as_array().unwrap() {
        assert!(matches!(
            finding["severity"].as_str(),
            Some("high" | "critical")
        ));
    }
}

#[test]
fn output_file_is_plain_text() {
    let file = std::env::temp_dir().join(format!("shorwatch-test-{}.txt", std::process::id()));
    let output = shorwatch(&[
        "scan",
        &path("spring-app"),
        "--output",
        &file.display().to_string(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    assert!(text.contains("jvm.jca.rsa") && !text.contains('\x1b'));
}

#[test]
fn missing_path_is_an_error() {
    let output = shorwatch(&["scan", "definitely/not/here"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not exist"));
}

#[test]
fn rules_lists_every_builtin_rule() {
    let output = shorwatch(&["rules"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(
        text.contains("jvm.jca.aes-128") && text.contains("config.spring-boot.tls-key-exchange")
    );
    assert!(text.trim_end().ends_with("127 rules"), "{text}");
}

fn examples(folder: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../examples")
        .join(folder)
        .display()
        .to_string()
}

/// The examples are documentation: if a rule change alters what they show,
/// update `examples/README.md` and `examples/output/` together.
#[test]
fn examples_keep_showing_what_their_readme_describes() {
    let output = shorwatch(&["scan", &examples("spring-service"), "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["summary"]["findings"], 17);
    assert_eq!(report["summary"]["in_transition"], 1);
    assert_eq!(report["summary"]["fixable"], 1);

    let output = shorwatch(&["scan", &examples("algorithms"), "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        report["summary"]["files_with_findings"], 11,
        "every example file is flagged"
    );
}

#[test]
fn cbom_inventories_algorithms_with_their_occurrences() {
    let output = shorwatch(&["scan", &examples("spring-service"), "--format", "cbom"]);
    let bom: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.6");
    let components = bom["components"].as_array().unwrap();
    for component in components {
        assert_eq!(component["type"], "cryptographic-asset");
        let level =
            &component["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"];
        assert!(level.is_u64(), "{component}");
        assert!(
            !component["evidence"]["occurrences"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    let rsa = components.iter().find(|c| c["name"] == "RSA").unwrap();
    assert_eq!(
        rsa["cryptoProperties"]["algorithmProperties"]["primitive"],
        "pke"
    );
}

/// `.properties` files are often ISO-8859-1 (found in the wild in Keycloak and
/// Spring Security): they are decoded, not skipped.
#[test]
fn latin1_properties_are_scanned() {
    let dir = std::env::temp_dir().join(format!("shorwatch-latin1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("application.properties");
    // `# Café` in ISO-8859-1: 0xE9 is not valid UTF-8 on its own.
    std::fs::write(&file, b"# Caf\xe9\njwt.algorithm=RS256\n").unwrap();

    let output = shorwatch(&["scan", &dir.display().to_string(), "--format", "json"]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["findings"][0]["rule_id"], "config.app.jose-rsa");
}

#[test]
fn test_code_is_labelled_and_can_be_excluded() {
    let dir = std::env::temp_dir().join(format!("shorwatch-roles-{}", std::process::id()));
    for (path, code) in [
        (
            "src/main/java/Keys.java",
            "class Keys { Object k() throws Exception { return java.security.KeyPairGenerator.getInstance(\"RSA\"); } }",
        ),
        (
            "src/test/java/KeysTest.java",
            "class KeysTest { Object k() throws Exception { return java.security.KeyPairGenerator.getInstance(\"EC\"); } }",
        ),
    ] {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, code).unwrap();
    }
    let root = dir.display().to_string();

    let all = shorwatch(&["scan", &root, "--format", "json"]);
    let only_production = shorwatch(&["scan", &root, "--format", "json", "--exclude-tests"]);
    std::fs::remove_dir_all(&dir).unwrap();

    let all: serde_json::Value = serde_json::from_str(&stdout(&all)).unwrap();
    assert_eq!(all["summary"]["findings"], 2);
    assert_eq!(all["summary"]["in_tests"], 1);
    let roles: Vec<_> = all["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["role"].clone())
        .collect();
    assert_eq!(roles, ["production", "test"]);

    let only_production: serde_json::Value =
        serde_json::from_str(&stdout(&only_production)).unwrap();
    assert_eq!(only_production["summary"]["files_scanned"], 1);
    assert_eq!(only_production["findings"][0]["rule_id"], "jvm.jca.rsa");
}

#[test]
fn classpath_entries_that_cannot_be_read_only_warn() {
    let dir = std::env::temp_dir().join(format!("shorwatch-cp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let broken = dir.join("broken.jar");
    std::fs::write(&broken, b"not a zip").unwrap();
    let list = dir.join("cp.txt");
    std::fs::write(&list, format!("{}\n", broken.display())).unwrap();

    let at_list = format!("@{}", list.display());
    let missing = dir.join("missing.jar").display().to_string();
    let output = shorwatch(&[
        "scan",
        &path("dh/Clean.java"),
        "--classpath",
        &at_list,
        "--classpath",
        &missing,
    ]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("skipping") && stderr.contains("broken.jar"),
        "{stderr}"
    );
    assert!(stderr.contains("missing.jar"), "{stderr}");
    assert!(stderr.contains("classpath: 0 types"), "{stderr}");
}
