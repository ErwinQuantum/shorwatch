//! Unit tests of the Kotlin frontend, on small in-memory sources.

use shorwatch_core::ir::TypeRef;

use super::literals::int_value;
use super::*;

fn lower(source: &str) -> SourceUnit {
    KotlinFrontend.lower("Test.kt", source).unwrap()
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

fn constructs(unit: &SourceUnit) -> Vec<(TypeRef, Vec<ArgValue>)> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Construct { ty, args } => {
                Some((ty.clone(), args.iter().map(|a| a.value.clone()).collect()))
            }
            _ => None,
        })
        .collect()
}

fn fields(unit: &SourceUnit) -> Vec<(TypeRef, String)> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Field { owner, name, .. } => Some((owner.clone(), name.clone())),
            _ => None,
        })
        .collect()
}

fn call(
    receiver: &str,
    method: &str,
    args: Vec<ArgValue>,
) -> (Option<TypeRef>, String, Vec<ArgValue>) {
    (Some(TypeRef::qualified(receiver)), method.to_owned(), args)
}

fn str(value: &str) -> ArgValue {
    ArgValue::Str(value.into())
}

#[test]
fn lowers_a_static_factory_call() {
    let unit = lower(
        r#"
        import java.security.KeyPairGenerator
        fun run() {
            KeyPairGenerator.getInstance("RSA")
        }
        "#,
    );
    assert_eq!(
        calls(&unit),
        [call(
            "java.security.KeyPairGenerator",
            "getInstance",
            vec![str("RSA")]
        )]
    );
}

#[test]
fn infers_variable_types_from_factories_and_declarations() {
    let unit = lower(
        r#"
        import javax.crypto.KeyGenerator
        import java.security.KeyPairGenerator
        class A {
            private val pairs: KeyPairGenerator? = null
            fun run() {
                val kg = KeyGenerator.getInstance("AES")
                kg.init(128)
                this.pairs.initialize(2048)
            }
        }
        "#,
    );
    let calls = calls(&unit);
    assert!(calls.contains(&call(
        "javax.crypto.KeyGenerator",
        "init",
        vec![ArgValue::Int(128)]
    )));
    assert!(calls.contains(&call(
        "java.security.KeyPairGenerator",
        "initialize",
        vec![ArgValue::Int(2048)]
    )));
}

#[test]
fn constructors_need_no_new() {
    let unit = lower(
        r#"
        import java.security.spec.ECGenParameterSpec
        fun run() {
            ECGenParameterSpec("secp256r1")
            org.bouncycastle.crypto.engines.RSAEngine()
        }
        "#,
    );
    assert_eq!(
        constructs(&unit),
        [
            (
                TypeRef::qualified("java.security.spec.ECGenParameterSpec"),
                vec![str("secp256r1")]
            ),
            (
                TypeRef::qualified("org.bouncycastle.crypto.engines.RSAEngine"),
                vec![]
            ),
        ]
    );
}

#[test]
fn resolves_val_constants_and_companion_members() {
    let unit = lower(
        r#"
        import java.security.KeyPairGenerator
        const val TOP = "DSA"
        class A {
            fun run() {
                KeyPairGenerator.getInstance(ALG)
                KeyPairGenerator.getInstance(A.ALG)
                KeyPairGenerator.getInstance(TOP)
                KeyPairGenerator.getInstance(mutable)
            }
            companion object {
                private const val ALG = "RSA"
            }
            var mutable = "EC"
        }
        "#,
    );
    let args: Vec<_> = calls(&unit).into_iter().map(|(_, _, args)| args).collect();
    assert_eq!(
        args[..3],
        [vec![str("RSA")], vec![str("RSA")], vec![str("DSA")]]
    );
    // Not a constant, but data flow knows its initializer.
    assert_eq!(args[3][0].texts(), ["EC"]);
    assert!(matches!(args[3][0], ArgValue::OneOf(_)));
}

#[test]
fn templates_with_interpolation_are_not_constants() {
    let unit = lower(
        r#"
        fun run(bits: Int) {
            Cipher.getInstance("AES_$bits/GCM/NoPadding")
            Cipher.getInstance("AES_${bits}/GCM/NoPadding")
            Cipher.getInstance("""AES_$bits""")
            Cipher.getInstance("DESede\u002FCBC \$5")
        }
        "#,
    );
    let args: Vec<_> = calls(&unit).into_iter().map(|(_, _, args)| args).collect();
    assert_eq!(
        args,
        [
            vec![ArgValue::Unknown],
            vec![ArgValue::Unknown],
            vec![ArgValue::Unknown],
            vec![str("DESede/CBC $5")]
        ]
    );
}

#[test]
fn member_imports_work_like_static_imports() {
    let unit = lower(
        r#"
        import com.nimbusds.jose.JWSAlgorithm.RS256
        import com.auth0.jwt.algorithms.Algorithm.RSA256
        import java.security.KeyPairGenerator as Kpg
        fun run() {
            val alg = RS256
            RSA256(publicKey, privateKey)
            Kpg.getInstance("EC")
        }
        "#,
    );
    assert_eq!(
        fields(&unit),
        [(
            TypeRef::qualified("com.nimbusds.jose.JWSAlgorithm"),
            "RS256".to_owned()
        )]
    );
    let calls = calls(&unit);
    assert_eq!(
        calls[0].0,
        Some(TypeRef::qualified("com.auth0.jwt.algorithms.Algorithm"))
    );
    assert_eq!(
        calls[1],
        call(
            "java.security.KeyPairGenerator",
            "getInstance",
            vec![str("EC")]
        )
    );
}

#[test]
fn records_static_field_reads_but_not_instance_ones() {
    let unit = lower(
        r#"
        import com.nimbusds.jose.JWSAlgorithm
        import io.jsonwebtoken.Jwts
        class A {
            val local = JWSAlgorithm.ES256
            fun run(key: Key, holder: Holder) {
                Jwts.builder().signWith(key, Jwts.SIG.RS256)
                holder.alg
                this.local
            }
        }
        "#,
    );
    assert_eq!(
        fields(&unit),
        [
            (
                TypeRef::qualified("com.nimbusds.jose.JWSAlgorithm"),
                "ES256".to_owned()
            ),
            (
                TypeRef::qualified("io.jsonwebtoken.Jwts.SIG"),
                "RS256".to_owned()
            ),
        ]
    );
}

#[test]
fn scope_functions_pass_their_receiver_to_the_lambda() {
    let unit = lower(
        r#"
        import javax.crypto.KeyGenerator
        import java.security.KeyPairGenerator
        fun run(gen: KeyPairGenerator) {
            val kg = KeyGenerator.getInstance("AES").apply { init(128) }
            KeyPairGenerator.getInstance("RSA").also { it.initialize(1024) }
            gen.let { g -> g.initialize(2048) }
            with(gen) { initialize(3072) }
            kg.init(192)
        }
        "#,
    );
    let calls = calls(&unit);
    for expected in [
        call(
            "javax.crypto.KeyGenerator",
            "init",
            vec![ArgValue::Int(128)],
        ),
        call(
            "java.security.KeyPairGenerator",
            "initialize",
            vec![ArgValue::Int(1024)],
        ),
        call(
            "java.security.KeyPairGenerator",
            "initialize",
            vec![ArgValue::Int(2048)],
        ),
        call(
            "java.security.KeyPairGenerator",
            "initialize",
            vec![ArgValue::Int(3072)],
        ),
        call(
            "javax.crypto.KeyGenerator",
            "init",
            vec![ArgValue::Int(192)],
        ),
    ] {
        assert!(
            calls.contains(&expected),
            "missing {expected:?} in {calls:#?}"
        );
    }
}

#[test]
fn named_arguments_keep_their_value() {
    let unit = lower(
        r#"
        fun run() {
            Signature.getInstance(algorithm = "SHA256withRSA")
        }
        "#,
    );
    assert_eq!(calls(&unit)[0].2, [str("SHA256withRSA")]);
}

#[test]
fn records_values_injected_with_at_value() {
    let unit = lower(
        r#"
        class Signer(@Value("\${jwt.alg:RS256}") private val alg: String) {
            @Value("\${app.cipher}")
            lateinit var cipher: String

            fun sign(@Value("\${app.curve}") curve: String) {
                JWSAlgorithm.parse(alg)
                Cipher.getInstance(cipher)
                ECGenParameterSpec(curve)
            }
        }
        "#,
    );
    let injected = |key: &str, default: Option<&str>| ArgValue::Injected {
        key: key.into(),
        default: default.map(Into::into),
        resolved: Vec::new(),
    };
    let calls = calls(&unit);
    assert_eq!(calls[0].2, [injected("jwt.alg", Some("RS256"))]);
    assert_eq!(calls[1].2, [injected("app.cipher", None)]);
    assert_eq!(constructs(&unit)[0].1, [injected("app.curve", None)]);
    let via = unit.facts().iter().find_map(|f| match &f.kind {
        FactKind::Call { args, .. } => args[0].resolved_via.clone(),
        _ => None,
    });
    assert_eq!(via.as_deref(), Some("${jwt.alg}"));
}

#[test]
fn local_functions_shadow_member_imports() {
    let unit = lower(
        r#"
        import com.auth0.jwt.algorithms.Algorithm.RSA256
        fun run() { RSA256(a, b) }
        fun RSA256(a: Any, b: Any) = Unit
        "#,
    );
    assert_eq!(calls(&unit)[0].0, None);
}

#[test]
fn comments_produce_no_facts() {
    let unit = lower(
        r#"
        fun run() {
            // KeyPairGenerator.getInstance("RSA")
            /* Cipher.getInstance("RSA") */
        }
        "#,
    );
    assert!(unit.facts().is_empty());
}

#[test]
fn columns_count_code_points() {
    let unit = lower("val ñandú = \"é\"; fun f() { Cipher.getInstance(\"RSA\") }");
    let fact = unit
        .facts()
        .iter()
        .find(|f| matches!(f.kind, FactKind::Call { .. }))
        .unwrap();
    // 31 if counted in bytes: ñ, ú and é take two each.
    assert_eq!(fact.location.start.column, 28);
}

#[test]
fn decodes_integer_literals() {
    assert_eq!(int_value("2048"), Some(2048));
    assert_eq!(int_value("0x80"), Some(128));
    assert_eq!(int_value("0b1000_0000"), Some(128));
    assert_eq!(int_value("1_024L"), Some(1024));
    assert_eq!(int_value("256u"), Some(256));
    assert_eq!(int_value("010"), Some(10));
}

#[test]
fn records_scopes_imports_and_literals() {
    let unit = lower(
        r#"
        package com.example

        import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
        import javax.crypto.*

        object Kem {
            fun group() = "X25519MLKEM768"
            init { println("ready") }
        }
        "#,
    );
    insta::assert_yaml_snapshot!(unit);
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
fn calls_on_factory_made_receivers_know_their_origin() {
    let unit = lower(
        r#"
        import javax.crypto.KeyGenerator
        fun run(injected: KeyGenerator) {
            KeyGenerator.getInstance("AES").apply { init(128) }
            KeyGenerator.getInstance("HmacSHA256").also { it.init(128) }
            val kg = KeyGenerator.getInstance("DESede")
            kg.init(168)
            with(kg) { init(112) }
            injected.init(128)
        }
        "#,
    );
    assert_eq!(
        origins(&unit),
        [
            ("init".to_owned(), str("AES")),
            ("init".to_owned(), str("HmacSHA256")),
            ("init".to_owned(), str("DESede")),
            ("init".to_owned(), str("DESede")),
        ]
    );
}

#[test]
fn unimported_types_belong_to_the_package_or_on_demand_imports() {
    let owner = |source: &str| {
        lower(source)
            .facts()
            .iter()
            .find_map(|f| match &f.kind {
                FactKind::Field { owner, .. } => Some(owner.clone()),
                _ => None,
            })
            .unwrap()
    };
    let azure = "com.azure.security.keyvault.keys.models.KeyType";
    let same_package = owner(
        "package org.keycloak.crypto

fun t() = KeyType.RSA
",
    );
    assert!(same_package.is("org.keycloak.crypto.KeyType"));
    assert!(!same_package.is(azure));
    let on_demand = owner(
        "package com.acme

import com.azure.security.keyvault.keys.models.*

fun t() = KeyType.RSA
",
    );
    assert!(on_demand.is(azure));
}

/// `(method, methods chained after it)` of every call, in source order.
fn chains(unit: &SourceUnit) -> Vec<(String, Vec<String>)> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Call { method, chain, .. } => Some((method.clone(), chain.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_call_knows_which_methods_are_chained_after_it() {
    let unit = lower(
        r#"
            class A {
                fun run() {
                    Decoder.withUri(u).algorithm(a).build()
                    Decoder.withUri(u)
                    outer(Decoder.withUri(u))
                }
            }
        "#,
    );
    let chains = chains(&unit);
    let with_uri: Vec<_> = chains.iter().filter(|(m, _)| m == "withUri").collect();
    assert_eq!(with_uri[0].1, ["algorithm", "build"]);
    assert!(with_uri[1].1.is_empty());
    assert!(with_uri[2].1.is_empty());
    let algorithm = chains.iter().find(|(m, _)| m == "algorithm").unwrap();
    assert_eq!(algorithm.1, ["build"]);
}

/// What the enum's `name()` may return, as the names of its constants.
fn enum_names(unit: &SourceUnit, owner: &str, method: &str) -> Vec<String> {
    unit.methods()
        .iter()
        .find(|m| m.owner == owner && m.name == method)
        .map(|m| {
            m.returns
                .iter()
                .flat_map(|c| c.value.texts())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// The arguments of the constructions of `ty`, one list per construction.
fn constructions(unit: &SourceUnit, ty: &str) -> Vec<Vec<ArgValue>> {
    unit.facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Construct { ty: t, args } if t.is(ty) => {
                Some(args.iter().map(|a| a.value.clone()).collect())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn enum_entries_are_constructions_and_have_names() {
    let unit = lower(
        "enum class Kind(val jce: String) {
    LEGACY(\"RSA\"),
    SIGNING(\"EC\");
}
",
    );
    assert_eq!(
        constructions(&unit, "Kind"),
        [[ArgValue::Str("RSA".into())], [ArgValue::Str("EC".into())]]
    );
    assert_eq!(enum_names(&unit, "Kind", "name"), ["LEGACY", "SIGNING"]);
}

#[test]
fn a_constructor_property_is_read_like_an_accessor() {
    let unit = lower(
        "class Gen(val alg: String, other: String)
",
    );
    let names: Vec<_> = unit.methods().iter().map(|m| m.name.as_str()).collect();
    // `alg` is a property; `other` is only a parameter.
    assert!(names.contains(&"alg"));
    assert!(!names.contains(&"other"));
}
