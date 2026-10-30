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
