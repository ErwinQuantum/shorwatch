//! Files built to hurt the scanner: nesting deeper than any real file, and
//! sizes that make a quadratic pass visible.

use shorwatch_langs::{
    Frontend, JavaFrontend, KotlinFrontend, LangError, PropertiesFrontend, YamlFrontend,
};

fn too_deep(error: LangError) -> bool {
    matches!(error, LangError::TooDeep(..))
}

#[test]
fn java_nested_beyond_any_real_file_is_refused() {
    let source = format!(
        "class A {{ int x = {}1{}; }}",
        "(".repeat(5_000),
        ")".repeat(5_000)
    );
    let error = JavaFrontend.lower("A.java", &source).unwrap_err();
    assert!(too_deep(error));
}

#[test]
fn java_concatenation_beyond_any_real_file_is_refused() {
    let source = format!(
        "class A {{ String x = \"a\"{}; }}",
        " + \"a\"".repeat(5_000)
    );
    let error = JavaFrontend.lower("A.java", &source).unwrap_err();
    assert!(too_deep(error));
}

#[test]
fn kotlin_nested_beyond_any_real_file_is_refused() {
    let source = format!("val x = {}1{}\n", "{ ".repeat(5_000), " }".repeat(5_000));
    let error = KotlinFrontend.lower("A.kt", &source).unwrap_err();
    assert!(too_deep(error));
}

#[test]
fn yaml_nested_beyond_any_real_file_is_refused() {
    let source = format!("a: {}{}\n", "[".repeat(5_000), "]".repeat(5_000));
    let error = YamlFrontend.lower("a.yml", &source).unwrap_err();
    assert!(too_deep(error));
}

#[test]
fn ordinary_nesting_is_not_refused() {
    let source = format!(
        "class A {{ int x = {}1{}; }}",
        "(".repeat(200),
        ")".repeat(200)
    );
    assert!(JavaFrontend.lower("A.java", &source).is_ok());
}

#[test]
fn a_properties_file_of_many_lines_is_lowered_with_the_right_positions() {
    let lines = 200_000;
    let source: String = (0..lines).map(|i| format!("k{i}=v\n")).collect();
    let unit = PropertiesFrontend.lower("big.properties", &source).unwrap();
    let last = unit.facts().last().unwrap();
    assert_eq!(unit.facts().len(), lines);
    assert_eq!(last.location.start.line, u32::try_from(lines).unwrap());
    assert_eq!(last.location.start.column, 9);
}

use std::time::{Duration, Instant};

use shorwatch_langs::{GradleFrontend, MavenFrontend, NuGetFrontend, VersionCatalogFrontend};

/// Runs `lower` and says how long it took: a pass that is quadratic in the
/// file would take minutes on these inputs.
fn timed<T>(lower: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let result = lower();
    (result, start.elapsed())
}

#[test]
fn a_large_gradle_script_is_read_in_linear_time() {
    let source = "implementation 'org.bouncycastle:bcprov-jdk18on:1.70'\n".repeat(50_000);
    let (unit, took) = timed(|| GradleFrontend.lower("build.gradle", &source).unwrap());
    assert_eq!(unit.facts().len(), 50_000);
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn a_gradle_script_of_unclosed_strings_and_comments_ends() {
    for source in [
        "'".repeat(1_000_000),
        "\"\"\"".repeat(300_000),
        "/*".repeat(500_000),
        "implementation(".repeat(200_000),
        "implementation platform(platform(platform(".repeat(50_000),
    ] {
        let (unit, took) = timed(|| GradleFrontend.lower("build.gradle", &source).unwrap());
        assert!(unit.facts().is_empty());
        assert!(took < Duration::from_secs(10), "{took:?}");
    }
}

#[test]
fn a_property_that_refers_to_itself_does_not_blow_up_a_pom() {
    let dependencies = "<dependency><groupId>a</groupId><artifactId>b</artifactId><version>${bomb}</version></dependency>"
        .repeat(5_000);
    let source = format!(
        "<project><properties><bomb>${{bomb}}${{bomb}}</bomb></properties><dependencies>{dependencies}</dependencies></project>"
    );
    let (unit, took) = timed(|| MavenFrontend.lower("pom.xml", &source).unwrap());
    assert_eq!(unit.facts().len(), 5_000);
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn a_property_that_refers_to_itself_does_not_blow_up_a_project_file() {
    let packages = r#"<PackageReference Include="b" Version="$(bomb)" />"#.repeat(5_000);
    let source = format!(
        "<Project><PropertyGroup><bomb>$(bomb)$(bomb)</bomb></PropertyGroup><ItemGroup>{packages}</ItemGroup></Project>"
    );
    let (unit, took) = timed(|| NuGetFrontend.lower("a.csproj", &source).unwrap());
    assert_eq!(unit.facts().len(), 5_000);
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn a_project_file_of_many_packages_is_read_in_linear_time() {
    let packages = "<PackageReference Include=\"b\" Version=\"1\" />
"
    .repeat(30_000);
    let source = format!("<Project><ItemGroup>{packages}</ItemGroup></Project>");
    let (unit, took) = timed(|| NuGetFrontend.lower("a.csproj", &source).unwrap());
    assert_eq!(unit.facts().len(), 30_000);
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn a_pom_of_many_dependencies_is_read_in_linear_time() {
    let dependencies = "<dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency>\n"
        .repeat(30_000);
    let source = format!("<project><dependencies>{dependencies}</dependencies></project>");
    let (unit, took) = timed(|| MavenFrontend.lower("pom.xml", &source).unwrap());
    assert_eq!(unit.facts().len(), 30_000);
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn a_catalog_of_nested_braces_is_skipped_not_followed() {
    let line = format!("x = {}\n", "{ a = ".repeat(500_000));
    let source = format!("[libraries]\n{line}ok = \"a:b:1\"\n");
    let (unit, took) = timed(|| {
        VersionCatalogFrontend
            .lower("libs.versions.toml", &source)
            .unwrap()
    });
    assert_eq!(unit.facts().len(), 1);
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn a_large_catalog_is_read_in_linear_time() {
    let libraries: String = (0..50_000)
        .map(|i| format!("lib{i} = {{ module = \"g:a{i}\", version.ref = \"v\" }}\n"))
        .collect();
    let source = format!("[versions]\nv = \"1.0\"\n[libraries]\n{libraries}");
    let (unit, took) = timed(|| {
        VersionCatalogFrontend
            .lower("libs.versions.toml", &source)
            .unwrap()
    });
    assert_eq!(unit.facts().len(), 50_000);
    assert!(took < Duration::from_secs(10), "{took:?}");
}
