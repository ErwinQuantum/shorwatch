//! End-to-end tests: run the real `shorwatch` binary on the rule fixtures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures(folder: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../shorwatch-rules/tests/fixtures")
        .join(folder)
}

/// Runs the binary with its own temporary folder, so the reports tests
/// write never become the developer's last report (`shorwatch open`), and
/// outside any CI system, so `shorwatch ci` links local files.
fn shorwatch(args: &[&str]) -> Output {
    let tmp = env!("CARGO_TARGET_TMPDIR");
    let mut command = Command::new(env!("CARGO_BIN_EXE_shorwatch"));
    for ci in [
        "GITHUB_ACTIONS",
        "GITHUB_STEP_SUMMARY",
        "GITLAB_CI",
        "JENKINS_URL",
        "TF_BUILD",
    ] {
        command.env_remove(ci);
    }
    command
        .args(args)
        .env("NO_COLOR", "1")
        .env("TMP", tmp)
        .env("TEMP", tmp)
        .env("TMPDIR", tmp)
        .env("XDG_CACHE_HOME", tmp)
        .env("HOME", tmp)
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
    let output = shorwatch(&["scan", &path("spring-app"), "--details"]);
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
fn the_default_view_counts_and_the_others_show_findings() {
    let blocks = |text: &str| text.matches("──▶").count();
    let summary = stdout(&shorwatch(&["scan", &path("spring-app")]));
    assert!(summary.contains("14 findings in 10 files"), "{summary}");
    assert!(summary.contains("--html"), "{summary}");
    assert_eq!(blocks(&summary), 0);

    let overview = stdout(&shorwatch(&["scan", &path("spring-app"), "--overview"]));
    assert!(overview.contains("Files with findings"), "{overview}");
    assert!(overview.contains("Most urgent"), "{overview}");
    assert_eq!(blocks(&overview), 3);

    let details = stdout(&shorwatch(&["scan", &path("spring-app"), "--details"]));
    assert_eq!(blocks(&details), 14);
    assert!(!details.contains("Most urgent"));
}

#[test]
fn html_report_is_written_beside_any_format_and_linked() {
    let file = std::env::temp_dir().join(format!("shorwatch-test-{}.html", std::process::id()));
    let output = shorwatch(&[
        "scan",
        &path("spring-app"),
        "--format",
        "sarif",
        "--html",
        &file.display().to_string(),
    ]);
    let html = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    assert!(html.contains("shorwatch-data"));
    serde_json::from_str::<serde_json::Value>(&stdout(&output)).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("fail the scan (exit code 1)"), "{stderr}");
    assert!(stderr.contains("file://"), "{stderr}");

    let output = shorwatch(&[
        "scan",
        &path("spring-app"),
        "--report-url",
        "https://ci.example/run/7",
    ]);
    assert!(stdout(&output).contains("Report   https://ci.example/run/7"));
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

    // spring-app has high, medium and low findings: still reported, but
    // only critical ones would fail.
    let critical = shorwatch(&["scan", &path("spring-app"), "--fail-severity", "critical"]);
    assert_eq!(critical.status.code(), Some(0));
    assert!(stdout(&critical).contains("14 findings"));
    assert!(critical.stderr.is_empty());
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
        "--details",
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
    assert!(text.trim_end().ends_with("131 rules"), "{text}");
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
    let all = bom["components"].as_array().unwrap();
    // The example's `pom.xml` adds its libraries, as components of their own.
    let libraries: Vec<_> = all.iter().filter(|c| c["type"] == "library").collect();
    assert_eq!(libraries.len(), 5);
    assert!(
        libraries
            .iter()
            .all(|c| c["purl"].as_str().unwrap().starts_with("pkg:maven/"))
    );
    let components: Vec<_> = all.iter().filter(|c| c["type"] != "library").collect();
    for component in &components {
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

    let output = shorwatch(&[
        "scan",
        &dir.display().to_string(),
        "--format",
        "json",
        "--fail-on",
        "never",
    ]);
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

#[test]
fn open_needs_a_report_that_exists() {
    let output = shorwatch(&["open", "definitely/not/here.html"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not exist"));
}

#[test]
fn without_a_command_it_scans() {
    let output = shorwatch(&[&path("spring-app"), "--fail-on", "never"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("14 findings in 10 files"));
}

#[test]
fn ci_writes_sarif_and_html_and_links_the_report() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ci-report");
    let output = shorwatch(&[
        "ci",
        &path("spring-app"),
        "--out-dir",
        &out.display().to_string(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let sarif = std::fs::read_to_string(out.join("report.sarif")).unwrap();
    serde_json::from_str::<serde_json::Value>(&sarif).unwrap();
    assert!(out.join("report.html").is_file());
    let log = stdout(&output);
    assert!(log.contains("14 findings in 10 files"), "{log}");
    assert!(log.contains("Report   file://"), "{log}");
    assert!(!log.contains("--details"), "no terminal hints in CI: {log}");
    // The verdict follows the summary in the same stream.
    assert!(log.contains("fail the scan (exit code 1)"), "{log}");
    assert!(log.contains("Report file://"), "{log}");
}

/// A project with a POM, a Gradle script and a version catalog, written to a
/// folder of its own: build files are found by name, and their libraries are
/// an inventory (never findings, so the scan stays clean).
#[test]
fn build_files_are_inventoried_not_reported_as_findings() {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("build-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("gradle")).unwrap();
    std::fs::write(
        dir.join("pom.xml"),
        "<project><properties><bc>1.70</bc></properties><dependencies>\n\
         <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>${bc}</version></dependency>\n\
         <dependency><groupId>com.acme</groupId><artifactId>widgets</artifactId><version>1</version></dependency>\n\
         </dependencies></project>",
    )
    .unwrap();
    std::fs::write(
        dir.join("build.gradle.kts"),
        "dependencies {\n    implementation(\"com.nimbusds:nimbus-jose-jwt:9.37\")\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle/libs.versions.toml"),
        "[versions]\njsch = \"0.1.55\"\n[libraries]\njsch = { module = \"com.jcraft:jsch\", version.ref = \"jsch\" }\n",
    )
    .unwrap();
    // Not a build file by name: must not be read.
    std::fs::write(
        dir.join("other.xml"),
        "<dependency><groupId>org.bouncycastle</groupId></dependency>",
    )
    .unwrap();

    let output = shorwatch(&["scan", &dir.display().to_string(), "--format", "json"]);
    assert_eq!(output.status.code(), Some(0), "libraries are not findings");
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["summary"]["findings"], 0);
    assert_eq!(report["summary"]["files_scanned"], 3);
    assert_eq!(report["summary"]["libraries"], 3);
    assert_eq!(report["summary"]["libraries_too_old"], 1);
    let libraries: Vec<_> = report["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["library_id"].as_str().unwrap(),
                d["version"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        libraries,
        [
            ("nimbus-jose-jwt", "9.37"),
            ("jsch", "0.1.55"),
            ("bouncycastle", "1.70")
        ]
    );

    let text = stdout(&shorwatch(&["scan", &dir.display().to_string()]));
    assert!(
        text.contains("3 cryptographic libraries in the build files"),
        "{text}"
    );
    assert!(
        text.contains("1 before post-quantum support (BouncyCastle 1.70)"),
        "{text}"
    );

    let cbom: serde_json::Value = serde_json::from_str(&stdout(&shorwatch(&[
        "scan",
        &dir.display().to_string(),
        "--format",
        "cbom",
    ])))
    .unwrap();
    let purls: Vec<_> = cbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["purl"].as_str())
        .collect();
    assert!(
        purls.contains(&"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.70"),
        "{purls:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
