use super::*;
use crate::ir::{FactKind, Language, SourceUnit};

fn spec(id: &str, since: Option<&str>) -> LibrarySpec {
    LibrarySpec {
        id: id.to_owned(),
        name: id.to_owned(),
        role: Role::Provider,
        nuget: Vec::new(),
        matches: vec![Coordinates {
            group: r"^org\.bouncycastle$".to_owned(),
            artifact: r"^bcprov-jdk(15on|18on)$".to_owned(),
        }],
        post_quantum: since.map(|since| PostQuantumSpec {
            since: since.to_owned(),
            algorithms: vec!["ML-KEM".to_owned()],
        }),
        summary: "A provider.".to_owned(),
        references: Vec::new(),
    }
}

fn unit_with(group: &str, artifact: &str, version: Option<&str>) -> SourceUnit {
    let mut unit = SourceUnit::new("pom.xml", Language::Maven);
    unit.push(
        FactKind::Dependency {
            group: group.to_owned(),
            artifact: artifact.to_owned(),
            version: version.map(str::to_owned),
            scope: None,
        },
        SourceUnit::ROOT,
        Location::line(7, 1, 1),
    );
    unit
}

fn found(version: Option<&str>) -> Vec<Dependency> {
    let catalog = LibraryCatalog::compile(vec![spec("bouncycastle", Some("1.79"))]).unwrap();
    dependencies(
        &unit_with("org.bouncycastle", "bcprov-jdk18on", version),
        &catalog,
    )
}

#[test]
fn a_known_library_is_inventoried_with_where_it_is_declared() {
    let found = found(Some("1.70"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].library_id, "bouncycastle");
    assert_eq!(found[0].path, "pom.xml");
    assert_eq!(found[0].location.start.line, 7);
}

fn nuget_spec() -> LibrarySpec {
    LibrarySpec {
        matches: Vec::new(),
        nuget: vec![r"^BouncyCastle\.Cryptography$".to_owned()],
        ..spec("bouncycastle-net", Some("2.5.0"))
    }
}

fn nuget_unit(id: &str, version: Option<&str>) -> SourceUnit {
    let mut unit = SourceUnit::new("App.csproj", Language::NuGet);
    unit.push(
        FactKind::Dependency {
            group: String::new(),
            artifact: id.to_owned(),
            version: version.map(str::to_owned),
            scope: None,
        },
        SourceUnit::ROOT,
        Location::line(9, 1, 1),
    );
    unit
}

#[test]
fn a_nuget_package_is_found_by_its_id_whatever_its_case() {
    let catalog = LibraryCatalog::compile(vec![spec("bouncycastle", None), nuget_spec()]).unwrap();
    let found = dependencies(
        &nuget_unit("bouncycastle.cryptography", Some("2.4.0")),
        &catalog,
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].library_id, "bouncycastle-net");
    assert_eq!(found[0].ecosystem, Ecosystem::NuGet);
    assert_eq!(
        found[0].post_quantum.as_ref().unwrap().support,
        Support::TooOld
    );
    let later = dependencies(
        &nuget_unit("BouncyCastle.Cryptography", Some("2.5.0")),
        &catalog,
    );
    assert_eq!(
        later[0].post_quantum.as_ref().unwrap().support,
        Support::Ready
    );
}

#[test]
fn maven_coordinates_and_nuget_ids_do_not_cross() {
    let catalog = LibraryCatalog::compile(vec![spec("bouncycastle", None), nuget_spec()]).unwrap();
    // A package id in a POM, and Maven coordinates in a project file.
    let mut pom = unit_with("", "BouncyCastle.Cryptography", Some("2.5.0"));
    assert!(dependencies(&pom, &catalog).is_empty());
    pom = nuget_unit("bcprov-jdk18on", Some("1.70"));
    assert!(dependencies(&pom, &catalog).is_empty());
}

#[test]
fn an_unknown_library_is_not() {
    let catalog = LibraryCatalog::compile(vec![spec("bouncycastle", None)]).unwrap();
    let unit = unit_with("com.acme", "widgets", Some("1.0"));
    assert!(dependencies(&unit, &catalog).is_empty());
}

#[test]
fn both_coordinates_must_match() {
    let catalog = LibraryCatalog::compile(vec![spec("bouncycastle", None)]).unwrap();
    let unit = unit_with("org.bouncycastle", "bcutil-jdk18on", Some("1.80"));
    assert!(dependencies(&unit, &catalog).is_empty());
}

fn support(version: Option<&str>) -> Support {
    found(version)[0].post_quantum.as_ref().unwrap().support
}

#[test]
fn a_version_before_the_first_with_post_quantum_is_too_old() {
    assert_eq!(support(Some("1.70")), Support::TooOld);
    assert_eq!(support(Some("1.78.1")), Support::TooOld);
}

#[test]
fn the_first_version_and_later_ones_are_ready() {
    assert_eq!(support(Some("1.79")), Support::Ready);
    assert_eq!(support(Some("1.80")), Support::Ready);
    assert_eq!(support(Some("2.0.0-SNAPSHOT")), Support::Ready);
}

#[test]
fn a_version_that_is_not_a_number_is_unknown_never_guessed() {
    for version in [
        None,
        Some("${bc.version}"),
        Some("1.+"),
        Some("[1.70,2.0)"),
        Some("latest.release"),
    ] {
        assert_eq!(support(version), Support::Unknown, "{version:?}");
    }
}

#[test]
fn a_library_without_a_post_quantum_version_claims_nothing() {
    let catalog = LibraryCatalog::compile(vec![spec("bouncycastle", None)]).unwrap();
    let unit = unit_with("org.bouncycastle", "bcprov-jdk18on", Some("1.70"));
    assert_eq!(dependencies(&unit, &catalog)[0].post_quantum, None);
}

#[test]
fn versions_compare_by_their_leading_numbers() {
    assert_eq!(version::at_least("1.79", "1.79"), Some(true));
    assert_eq!(version::at_least("1.79.0", "1.79"), Some(true));
    assert_eq!(version::at_least("1.8", "1.79"), Some(false));
    assert_eq!(version::at_least("1.100", "1.79"), Some(true));
    assert_eq!(version::at_least("7.0.0.RELEASE", "7.0"), Some(true));
    assert_eq!(version::at_least("3.1.5-SNAPSHOT", "3.2"), Some(false));
    assert_eq!(version::at_least("jdk18on", "1.0"), None);
    assert_eq!(version::at_least("99999999999999999999.1", "1.0"), None);
}

#[test]
fn a_catalog_rejects_what_would_misreport() {
    let compile = |f: fn(&mut LibrarySpec)| {
        let mut s = spec("a", Some("1.79"));
        f(&mut s);
        LibraryCatalog::compile(vec![s]).unwrap_err()
    };
    assert!(matches!(
        compile(|s| s.matches[0].group = "(".to_owned()),
        LibraryError::InvalidRegex { .. }
    ));
    assert!(matches!(
        compile(|s| s.post_quantum.as_mut().unwrap().since = "soon".to_owned()),
        LibraryError::InvalidVersion { .. }
    ));
    assert!(matches!(
        compile(|s| s.matches.clear()),
        LibraryError::Empty {
            field: "matches",
            ..
        }
    ));
    assert!(matches!(
        compile(|s| s.references = vec![crate::rule::Reference {
            title: "x".to_owned(),
            url: "javascript:alert(1)".to_owned(),
        }]),
        LibraryError::ReferenceNotHttp(..)
    ));
    assert_eq!(
        LibraryCatalog::compile(vec![spec("a", None), spec("a", None)]).unwrap_err(),
        LibraryError::DuplicateId("a".to_owned())
    );
}
