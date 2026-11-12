//! Config frontend tests on small in-memory files.

use shorwatch_core::ir::{FactKind, SourceUnit};

use super::*;
use crate::Frontend;

fn entries(unit: &SourceUnit) -> Vec<(String, String, u32)> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Property { key, value } => {
                Some((key.clone(), value.clone(), f.location.start.line))
            }
            _ => None,
        })
        .collect()
}

fn owned(expected: &[(&str, &str, u32)]) -> Vec<(String, String, u32)> {
    expected
        .iter()
        .map(|(k, v, l)| ((*k).to_owned(), (*v).to_owned(), *l))
        .collect()
}

#[test]
fn flattens_yaml_like_spring() {
    let source = "\
# comment: ignored
spring:
  security:
    oauth2.resourceserver.jwt:
      jws-algorithms: [RS256, \"ES256\"]
jwt:
  algorithms:
    - PS256
    - 'Ed''25519'
  inline: { alg: RS512 }
  note: |
    multi
---
server.ssl.ciphers: TLS_RSA_WITH_AES_128_CBC_SHA
";
    let unit = YamlFrontend.lower("application.yml", source).unwrap();
    assert_eq!(
        entries(&unit),
        owned(&[
            (
                "spring.security.oauth2.resourceserver.jwt.jws-algorithms[0]",
                "RS256",
                5
            ),
            (
                "spring.security.oauth2.resourceserver.jwt.jws-algorithms[1]",
                "ES256",
                5
            ),
            ("jwt.algorithms[0]", "PS256", 8),
            ("jwt.algorithms[1]", "Ed'25519", 9),
            ("jwt.inline.alg", "RS512", 10),
            ("jwt.note", "multi", 11),
            ("server.ssl.ciphers", "TLS_RSA_WITH_AES_128_CBC_SHA", 14),
        ])
    );
}

#[test]
fn yaml_value_location_points_at_the_value() {
    let unit = YamlFrontend.lower("a.yml", "jwt:\n  alg: RS256\n").unwrap();
    let start = unit.facts()[0].location.start;
    assert_eq!((start.line, start.column), (2, 8));
}

#[test]
fn parses_properties_syntax() {
    let source = "\
# comment
! also a comment
jwt.algorithm=RS256
server.ssl.ciphers : TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\\
    TLS_RSA_WITH_AES_256_CBC_SHA
key\\ with\\ spaces value
empty=
encrypt.key-store.location classpath:/server.jks
";
    let unit = PropertiesFrontend
        .lower("application.properties", source)
        .unwrap();
    assert_eq!(
        entries(&unit),
        owned(&[
            ("jwt.algorithm", "RS256", 3),
            (
                "server.ssl.ciphers",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA",
                4
            ),
            ("key with spaces", "value", 6),
            ("empty", "", 7),
            ("encrypt.key-store.location", "classpath:/server.jks", 8),
        ])
    );
    let start = unit.facts()[0].location.start;
    assert_eq!((start.line, start.column), (3, 15));
}

#[test]
fn handles_crlf_line_endings() {
    let unit = PropertiesFrontend
        .lower("a.properties", "a=1\r\nb=2\r\n")
        .unwrap();
    assert_eq!(entries(&unit), owned(&[("a", "1", 1), ("b", "2", 2)]));
}

fn json(source: &str) -> SourceUnit {
    JsonFrontend.lower("appsettings.json", source).unwrap()
}

#[test]
fn flattens_json_with_dots_and_indexes_at_the_value() {
    let unit = json(
        r#"{
  "Jwt": {
    "Algorithm": "RS256",
    "Algorithms": ["PS256", "ES256"],
    "Lifetime": 3600,
    "Enabled": true,
    "Nothing": null
  },
  "Logging": { "Level": { "Default": "Information" } }
}"#,
    );
    assert_eq!(
        entries(&unit),
        owned(&[
            ("Jwt.Algorithm", "RS256", 3),
            ("Jwt.Algorithms[0]", "PS256", 4),
            ("Jwt.Algorithms[1]", "ES256", 4),
            ("Jwt.Lifetime", "3600", 5),
            ("Jwt.Enabled", "true", 6),
            ("Logging.Level.Default", "Information", 9),
        ])
    );
    // Located at the value, quotes included.
    assert_eq!(unit.facts()[0].location.start.column, 18);
}

#[test]
fn json_tolerates_what_dotnet_does_comments_trailing_commas_and_a_bom() {
    let unit = json(
        "\u{feff}{\n  // the signing algorithm\n  \"Alg\": \"RS256\", /* old: HS256 */\n  \"List\": [\"a\",],\n}\n",
    );
    assert_eq!(
        entries(&unit),
        owned(&[("Alg", "RS256", 3), ("List[0]", "a", 4)])
    );
}

#[test]
fn json_strings_are_decoded() {
    let unit = json(r#"{ "a": "x\"y\\z\u0041\n" }"#);
    assert_eq!(entries(&unit)[0].1, "x\"y\\zA\n");
}

#[test]
fn a_json_array_of_objects_keeps_its_index() {
    let unit = json(r#"{ "Keys": [ { "Alg": "RS256" }, { "Alg": "ES256" } ] }"#);
    assert_eq!(
        entries(&unit).into_iter().map(|e| e.0).collect::<Vec<_>>(),
        ["Keys[0].Alg", "Keys[1].Alg"]
    );
}

#[test]
fn broken_or_hostile_json_is_an_error_or_partial_not_a_panic() {
    assert!(
        JsonFrontend
            .lower("a.json", "{ \"a\": \"unterminated")
            .is_err()
    );
    let deep = "[".repeat(10_000);
    assert!(JsonFrontend.lower("a.json", &deep).is_err());
    // Garbage keeps what came before it.
    let unit = json("{ \"a\": \"b\", ::: \"c\" }");
    assert_eq!(entries(&unit)[0].0, "a");
    json("");
    json("}}}]]]");
}

#[test]
fn appsettings_files_are_found_by_name() {
    use std::path::Path;
    for path in [
        "appsettings.json",
        "src/Api/appsettings.Production.json",
        "local.settings.json",
    ] {
        let frontend = crate::for_path(Path::new(path)).unwrap();
        assert_eq!(
            frontend.language(),
            shorwatch_core::Language::Json,
            "{path}"
        );
    }
    for path in ["package.json", "appsettings.txt", "myappsettings.json"] {
        assert!(crate::for_path(Path::new(path)).is_none(), "{path}");
    }
}
