//! Unit tests of the Java frontend, on small in-memory sources.

use shorwatch_core::ir::TypeRef;

use super::literals::{int_value, string_value};
use super::*;

fn lower(source: &str) -> SourceUnit {
    JavaFrontend.lower("Test.java", source).unwrap()
}

fn calls(unit: &SourceUnit) -> Vec<(Option<TypeRef>, String, Vec<ArgValue>)> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Call {
                receiver,
                method,
                args,
                ..
            } => Some((
                receiver.clone(),
                method.clone(),
                args.iter().map(|a| a.value.clone()).collect(),
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn lowers_a_static_factory_call() {
    let unit = lower(
        r#"
            import java.security.KeyPairGenerator;
            class A {
                void run() throws Exception {
                    KeyPairGenerator.getInstance("RSA");
                }
            }
            "#,
    );
    assert_eq!(
        calls(&unit),
        [(
            Some(TypeRef::qualified("java.security.KeyPairGenerator")),
            "getInstance".to_owned(),
            vec![ArgValue::Str("RSA".into())]
        )]
    );
}

#[test]
fn resolves_receiver_through_variable_type() {
    let unit = lower(
        r#"
            import javax.crypto.KeyGenerator;
            class A {
                void run() throws Exception {
                    KeyGenerator kg = KeyGenerator.getInstance("AES");
                    kg.init(128);
                    var other = KeyGenerator.getInstance("AES");
                    other.init(256);
                }
            }
            "#,
    );
    let init: Vec<_> = calls(&unit)
        .into_iter()
        .filter(|(_, m, _)| m == "init")
        .collect();
    let kg = TypeRef::qualified("javax.crypto.KeyGenerator");
    assert_eq!(
        init[0],
        (Some(kg.clone()), "init".into(), vec![ArgValue::Int(128)])
    );
    assert_eq!(init[1], (Some(kg), "init".into(), vec![ArgValue::Int(256)]));
}

#[test]
fn resolves_final_constants_declared_after_use() {
    let unit = lower(
        r#"
            class A {
                void run() throws Exception {
                    javax.crypto.Cipher.getInstance(TRANSFORMATION);
                    javax.crypto.Cipher.getInstance(A.TRANSFORMATION);
                    javax.crypto.Cipher.getInstance(mutable);
                }
                private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
                private String mutable = "RSA";
            }
            "#,
    );
    let FactKind::Call { args, .. } = &unit.facts()[0].kind else {
        panic!()
    };
    assert_eq!(args[0].value, ArgValue::Str("RSA/ECB/PKCS1Padding".into()));
    assert_eq!(args[0].resolved_via.as_deref(), Some("TRANSFORMATION"));

    let values: Vec<_> = calls(&unit)
        .into_iter()
        .map(|(_, _, a)| a[0].clone())
        .collect();
    assert_eq!(values[1], ArgValue::Str("RSA/ECB/PKCS1Padding".into()));
    // Not a constant, but data flow knows its initializer.
    assert_eq!(values[2].texts(), ["RSA"]);
    assert!(matches!(values[2], ArgValue::OneOf(_)));
}

#[test]
fn comments_produce_no_facts() {
    let unit = lower(
        r#"
            class A {
                // KeyPairGenerator.getInstance("RSA");
                /* Cipher.getInstance("RSA"); */
                void run() {}
            }
            "#,
    );
    assert!(unit.facts().is_empty());
}

#[test]
fn records_scopes_imports_and_literals() {
    let unit = lower(
        r#"
            import org.bouncycastle.pqc.crypto.mlkem.*;
            class Outer {
                class Inner {
                    String alg() { return "ML-KEM-768"; }
                }
            }
            "#,
    );
    insta::assert_yaml_snapshot!(unit);
}

#[test]
fn columns_count_code_points() {
    let unit =
        lower("class A { String s = \"ñ\"; void m() { /*ñ*/ Cipher.getInstance(\"RSA\"); } }");
    let call = unit
        .facts()
        .iter()
        .find(|f| matches!(f.kind, FactKind::Call { .. }))
        .unwrap();
    let prefix = "class A { String s = \"ñ\"; void m() { /*ñ*/ ";
    assert_eq!(
        call.location.start.column as usize,
        prefix.chars().count() + 1
    );
    assert_eq!(call.location.start_byte, prefix.len());
}

#[test]
fn decodes_escapes() {
    assert_eq!(string_value(r#""a\"b\\cA""#).as_deref(), Some("a\"b\\cA"));
    assert_eq!(int_value("0x80"), Some(128));
    assert_eq!(int_value("1_024L"), Some(1024));
}

fn fields(unit: &SourceUnit) -> Vec<(TypeRef, String)> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Field { owner, name } => Some((owner.clone(), name.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn records_static_field_reads() {
    let unit = lower(
        r#"
            import com.nimbusds.jose.JWSAlgorithm;
            import io.jsonwebtoken.Jwts;
            class A {
                void run() {
                    sign(JWSAlgorithm.RS256);
                    Jwts.SIG.ES256.keyPair().build();
                    sign(com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256);
                }
            }
            "#,
    );
    assert_eq!(
        fields(&unit),
        [
            (
                TypeRef::qualified("com.nimbusds.jose.JWSAlgorithm"),
                "RS256".into()
            ),
            (
                TypeRef::qualified("io.jsonwebtoken.Jwts.SIG"),
                "ES256".into()
            ),
            (
                TypeRef::qualified("com.nimbusds.jose.JWEAlgorithm"),
                "RSA_OAEP_256".into()
            ),
        ]
    );
}

#[test]
fn instance_fields_are_not_static_reads() {
    let unit = lower(
        r#"
            class A {
                Config config;
                void run(Options options) {
                    use(this.alg, config.alg, options.Alg, config.inner.Alg);
                }
            }
            "#,
    );
    assert!(fields(&unit).is_empty(), "{:?}", fields(&unit));
}

#[test]
fn resolves_static_imports() {
    let unit = lower(
        r#"
            import static com.nimbusds.jose.JWSAlgorithm.RS256;
            import static com.auth0.jwt.algorithms.Algorithm.RSA256;
            class A {
                void run(Object pub, Object priv) {
                    sign(RS256);
                    RSA256(pub, priv);
                }
                void shadowed() {
                    String RS256 = "local";
                    use(RS256);
                }
            }
            "#,
    );
    assert_eq!(
        fields(&unit),
        [(
            TypeRef::qualified("com.nimbusds.jose.JWSAlgorithm"),
            "RS256".into()
        )]
    );
    let algorithm = TypeRef::qualified("com.auth0.jwt.algorithms.Algorithm");
    assert!(
        calls(&unit)
            .iter()
            .any(|(r, m, _)| m == "RSA256" && r.as_ref() == Some(&algorithm))
    );
}

#[test]
fn records_values_injected_with_at_value() {
    let unit = lower(
        r##"
            import org.springframework.beans.factory.annotation.Value;
            class A {
                @Value("${jwt.algorithm:RS256}") private String alg;
                @Value("#{systemProperties['alg']}") private String spel;
                A(@Value("${jwt.key-size}") int bits) { init(bits); }
                void run() { parse(alg); parse(this.alg); parse(spel); }
            }
            "##,
    );
    let args: Vec<_> = unit
        .facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Call { args, .. } => Some(args[0].clone()),
            _ => None,
        })
        .collect();
    let injected = |key: &str, default: Option<&str>| ArgValue::Injected {
        key: key.into(),
        default: default.map(str::to_owned),
        resolved: vec![],
    };
    assert_eq!(args[0].value, injected("jwt.key-size", None));
    assert_eq!(args[1].value, injected("jwt.algorithm", Some("RS256")));
    assert_eq!(args[1].resolved_via.as_deref(), Some("${jwt.algorithm}"));
    assert_eq!(args[2].value, injected("jwt.algorithm", Some("RS256")));
    assert_eq!(args[3].value, ArgValue::Unknown);
}

#[test]
fn local_methods_shadow_static_imports() {
    let unit = lower(
        r#"
            import static com.auth0.jwt.algorithms.Algorithm.RSA256;
            class A {
                void run() { RSA256(); }
                void RSA256() {}
            }
            "#,
    );
    assert_eq!(calls(&unit)[0].0, None);
}

/// `(method, first factory argument)` of every call whose receiver origin is known.
fn origins(unit: &SourceUnit) -> Vec<(String, ArgValue)> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Call {
                method,
                receiver_origin: Some(origin),
                ..
            } => Some((method.clone(), origin.first()?.value.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn calls_on_factory_made_variables_know_their_origin() {
    let unit = lower(
        r#"
            import javax.crypto.KeyGenerator;
            class A {
                private static final String HMAC = "HmacSHA256";
                private final KeyGenerator field = KeyGenerator.getInstance("AES");
                void run(KeyGenerator injected) throws Exception {
                    KeyGenerator aes = KeyGenerator.getInstance("AES");
                    aes.init(128);
                    var mac = KeyGenerator.getInstance(HMAC);
                    mac.init(128);
                    this.field.init(192);
                    injected.init(128);
                }
            }
            "#,
    );
    assert_eq!(
        origins(&unit),
        [
            ("init".to_owned(), ArgValue::Str("AES".into())),
            ("init".to_owned(), ArgValue::Str("HmacSHA256".into())),
            ("init".to_owned(), ArgValue::Str("AES".into())),
        ]
    );
}

fn field_owners(unit: &SourceUnit) -> Vec<TypeRef> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Field { owner, .. } => Some(owner.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn unimported_types_belong_to_the_package_or_on_demand_imports() {
    let azure = "com.azure.security.keyvault.keys.models.KeyType";
    let same_package = lower(
        "package org.keycloak.crypto;
class A { Object t() { return KeyType.RSA; } }",
    );
    let owner = &field_owners(&same_package)[0];
    assert!(owner.is("org.keycloak.crypto.KeyType"));
    assert!(!owner.is(azure));

    let on_demand = lower(
        "package com.acme;
import com.azure.security.keyvault.keys.models.*;
class A { Object t() { return KeyType.RSA; } }",
    );
    assert!(field_owners(&on_demand)[0].is(azure));

    // A module import brings packages only the module graph knows.
    let module = lower(
        "package org.acme;\nimport module java.base;\nclass A { void r() throws Exception { KeyFactory.getInstance(\"RSA\"); } }",
    );
    let (receiver, ..) = &calls(&module)[0];
    assert!(receiver.as_ref().unwrap().is("java.security.KeyFactory"));
}

#[test]
fn literals_know_the_calls_they_are_passed_to() {
    let unit = lower(
        r#"
            class A {
                void run(Factory f) {
                    f.setExcludeCipherSuites(List.of("TLS_RSA_WITH_AES_128_CBC_SHA"));
                    f.apply(() -> log("inner"));
                    String s = "alone";
                }
            }
        "#,
    );
    let literals: Vec<(String, Vec<String>)> = unit
        .facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Literal { value, calls } => Some((value.clone(), calls.clone())),
            _ => None,
        })
        .collect();
    let owned = |calls: &[&str]| calls.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        literals,
        [
            (
                "TLS_RSA_WITH_AES_128_CBC_SHA".to_owned(),
                owned(&["of", "setExcludeCipherSuites"])
            ),
            // A lambda body is its own context.
            ("inner".to_owned(), owned(&["log"])),
            ("alone".to_owned(), owned(&[])),
        ]
    );
}
