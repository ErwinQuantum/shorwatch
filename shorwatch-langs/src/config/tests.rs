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
