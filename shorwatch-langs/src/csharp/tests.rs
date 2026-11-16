//! Unit tests of the C# frontend, on small in-memory sources.

use shorwatch_core::ir::TypeRef;

use super::literals::{int_value, string_value};
use super::*;

fn lower(source: &str) -> SourceUnit {
    CSharpFrontend.lower("Test.cs", source).unwrap()
}

type CallFact = (Option<TypeRef>, String, Vec<ArgValue>);

fn calls(unit: &SourceUnit) -> Vec<CallFact> {
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
fn a_using_names_a_namespace_the_type_may_come_from() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A { void Run() { RSA.Create(2048); } }
        "#,
    );
    let all = calls(&unit);
    assert_eq!(all.len(), 1);
    let (receiver, method, args) = all[0].clone();
    let receiver = receiver.unwrap();
    assert_eq!(method, "Create");
    assert_eq!(args, [ArgValue::Int(2048)]);
    assert!(receiver.is("System.Security.Cryptography.RSA"));
    assert!(!receiver.is("Other.Namespace.RSA"));
}

#[test]
fn a_fully_qualified_name_needs_no_using() {
    let unit = lower("class A { void Run() { System.Security.Cryptography.RSA.Create(); } }");
    let all = calls(&unit);
    assert_eq!(all.len(), 1);
    let receiver = all[0].0.clone().unwrap();
    assert!(receiver.is("System.Security.Cryptography.RSA"));
}

#[test]
fn aliases_expand_types_and_namespaces() {
    let unit = lower(
        r#"
        using R = System.Security.Cryptography.RSA;
        using Crypto = System.Security.Cryptography;
        class A { void Run() { R.Create(); Crypto.ECDsa.Create(); } }
        "#,
    );
    let receivers: Vec<_> = calls(&unit).into_iter().map(|c| c.0.unwrap()).collect();
    assert_eq!(
        receivers,
        [
            TypeRef::qualified("System.Security.Cryptography.RSA"),
            TypeRef::qualified("System.Security.Cryptography.ECDsa"),
        ]
    );
}

#[test]
fn resolves_receiver_through_variable_type() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A {
            void Run() {
                Aes aes = Aes.Create();
                aes.GenerateKey();
                var other = RSA.Create();
                other.ExportParameters(true);
            }
        }
        "#,
    );
    let all = calls(&unit);
    let receiver_of = |method: &str| all.iter().find(|c| c.1 == method).unwrap().0.clone();
    assert!(
        receiver_of("GenerateKey")
            .unwrap()
            .is("System.Security.Cryptography.Aes")
    );
    assert!(
        receiver_of("ExportParameters")
            .unwrap()
            .is("System.Security.Cryptography.RSA")
    );
}

#[test]
fn a_property_assignment_is_a_setter_call() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A { void Run() { Aes aes = Aes.Create(); aes.KeySize = 128; } }
        "#,
    );
    let setter = calls(&unit)
        .into_iter()
        .find(|c| c.1 == "set_KeySize")
        .unwrap();
    assert!(setter.0.unwrap().is("System.Security.Cryptography.Aes"));
    assert_eq!(setter.2, [ArgValue::Int(128)]);
}

#[test]
fn constructions_and_target_typed_new() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A {
            void Run() {
                var t = new TripleDESCryptoServiceProvider();
                ECDsa e = new();
                var r = new RSACryptoServiceProvider(1024);
            }
        }
        "#,
    );
    let types: Vec<_> = unit
        .facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Construct { ty, args } => Some((ty.clone(), args.len())),
            _ => None,
        })
        .collect();
    assert_eq!(types.len(), 3);
    assert!(
        types[0]
            .0
            .is("System.Security.Cryptography.TripleDESCryptoServiceProvider")
    );
    assert!(types[1].0.is("System.Security.Cryptography.ECDsa"));
    assert!(
        types[2]
            .0
            .is("System.Security.Cryptography.RSACryptoServiceProvider")
    );
    assert_eq!(types[2].1, 1);
}

#[test]
fn static_members_are_fields_and_invoked_methods_are_not() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A {
            void Run(byte[] d, RSA rsa) {
                var name = HashAlgorithmName.SHA1;
                rsa.SignData(d, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        "#,
    );
    let fields: Vec<_> = unit
        .facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Field { owner, name, .. } => Some((owner.name.clone(), name.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        fields,
        [
            ("HashAlgorithmName".to_owned(), "SHA1".to_owned()),
            ("HashAlgorithmName".to_owned(), "SHA256".to_owned()),
            ("RSASignaturePadding".to_owned(), "Pkcs1".to_owned()),
        ]
    );
}

#[test]
fn nested_types_keep_their_path() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A { void Run() { var c = ECCurve.NamedCurves.nistP256; } }
        "#,
    );
    let owner = unit
        .facts()
        .iter()
        .find_map(|f| match &f.kind {
            FactKind::Field { owner, name, .. } if name == "nistP256" => Some(owner.clone()),
            _ => None,
        })
        .unwrap();
    assert!(owner.is("System.Security.Cryptography.ECCurve.NamedCurves"));
}

#[test]
fn constants_resolve_into_arguments() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A {
            private const string Alg = "SHA1";
            private static readonly int Bits = 1024;
            void Run() { HashAlgorithm.Create(Alg); RSA.Create(Bits); }
        }
        "#,
    );
    let all = calls(&unit);
    assert_eq!(all[0].2, [ArgValue::Str("SHA1".into())]);
    assert_eq!(all[1].2, [ArgValue::Int(1024)]);
}

#[test]
fn the_chain_after_a_call_is_recorded() {
    let unit = lower("class A { void Run() { Foo.Start().WithAlg(1).Build(); } }");
    let chain = unit
        .facts()
        .iter()
        .find_map(|f| match &f.kind {
            FactKind::Call { method, chain, .. } if method == "Start" => Some(chain.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(chain, ["WithAlg", "Build"]);
}

#[test]
fn literals_know_the_calls_they_are_passed_to() {
    let unit = lower(r#"class A { void Run() { Foo.Set(Bar.Wrap("x")); } }"#);
    let calls = unit
        .facts()
        .iter()
        .find_map(|f| match &f.kind {
            FactKind::Literal { value, calls } if value == "x" => Some(calls.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(calls, ["Wrap", "Set"]);
}

#[test]
fn string_and_integer_literals() {
    assert_eq!(string_value(r#""a\n""#), Some("a\n".into()));
    assert_eq!(string_value(r#"@"a""b""#), Some("a\"b".into()));
    assert_eq!(string_value(r#""""abc""""#), Some("abc".into()));
    assert_eq!(string_value(r#""A""#), Some("A".into()));
    assert_eq!(string_value(r#"$"RS{x}""#), None);
    assert_eq!(int_value("0x800"), Some(2048));
    assert_eq!(int_value("1_024"), Some(1024));
    assert_eq!(int_value("2048UL"), Some(2048));
}

#[test]
fn a_broken_file_still_yields_the_parts_that_parse() {
    let unit =
        lower("using System.Security.Cryptography; class A { void Run() { RSA.Create(); ((( } ");
    assert_eq!(calls(&unit).len(), 1);
}

#[test]
fn a_field_read_knows_the_calls_it_is_passed_to() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A {
            void Run(byte[] pw, byte[] salt) {
                Rfc2898DeriveBytes.Pbkdf2(pw, salt, 10, HashAlgorithmName.SHA1, 32);
                var kdf = new Rfc2898DeriveBytes(pw, salt, 10, HashAlgorithmName.SHA256);
                var plain = HashAlgorithmName.SHA1;
            }
        }
        "#,
    );
    let reads: Vec<_> = unit
        .facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Field { name, calls, .. } => Some((name.clone(), calls.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        reads,
        [
            ("SHA1".to_owned(), vec!["Pbkdf2".to_owned()]),
            ("SHA256".to_owned(), vec!["Rfc2898DeriveBytes".to_owned()]),
            ("SHA1".to_owned(), Vec::new()),
        ]
    );
}

#[test]
fn an_object_initializer_sets_properties_of_the_new_object() {
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A {
            void Run() {
                var aes = new AesManaged { KeySize = 128, Padding = PaddingMode.PKCS7 };
                ECDsa e = new() { KeySize = 256 };
            }
        }
        "#,
    );
    let setters: Vec<_> = calls(&unit)
        .into_iter()
        .filter(|c| c.1.starts_with("set_"))
        .collect();
    assert_eq!(setters.len(), 3, "{setters:?}");
    assert!(
        setters[0]
            .0
            .as_ref()
            .unwrap()
            .is("System.Security.Cryptography.AesManaged")
    );
    assert_eq!(setters[0].1, "set_KeySize");
    assert_eq!(setters[0].2, [ArgValue::Int(128)]);
    assert!(
        setters[2]
            .0
            .as_ref()
            .unwrap()
            .is("System.Security.Cryptography.ECDsa")
    );
}

#[test]
fn an_initializer_assignment_is_not_an_assignment_to_a_local() {
    // `KeySize` below is a property of the new object; it must not feed the
    // variable of the same name.
    let unit = lower(
        r#"
        using System.Security.Cryptography;
        class A {
            void Run() {
                var KeySize = 256;
                var aes = new AesManaged { KeySize = 128 };
                Foo.Use(KeySize);
            }
        }
        "#,
    );
    let used = calls(&unit).into_iter().find(|c| c.1 == "Use").unwrap();
    assert_eq!(used.2[0].texts(), ["256"]);
}

#[test]
fn properties_and_primary_constructors_are_published_for_other_files() {
    let unit = lower(
        r#"
        namespace Acme;
        public class Options {
            public string Algorithm { get; set; } = "SHA1";
        }
        public class Hasher(string name) { }
        public record Policy(string Digest);
        "#,
    );
    let summaries: Vec<_> = unit
        .methods()
        .iter()
        .map(|m| (m.owner.clone(), m.name.clone()))
        .collect();
    assert!(
        summaries.contains(&("Acme.Options".to_owned(), "Algorithm".to_owned())),
        "{summaries:?}"
    );
}

/// The configuration keys the arguments of `Use` come from, `None` for an
/// argument that does not read configuration.
fn injected(source: &str) -> Vec<Option<(String, Option<String>)>> {
    fn key(value: &ArgValue) -> Option<(String, Option<String>)> {
        match value {
            ArgValue::Injected { key, default, .. } => Some((key.clone(), default.clone())),
            ArgValue::OneOf(candidates) => candidates.iter().find_map(|c| key(&c.value)),
            _ => None,
        }
    }
    calls(&lower(source))
        .into_iter()
        .filter(|c| c.1 == "Use")
        .flat_map(|c| c.2)
        .map(|v| key(&v))
        .collect()
}

#[test]
fn configuration_reads_are_injected_values_with_their_section_path() {
    let found = injected(
        r#"
        using Microsoft.Extensions.Configuration;
        class A {
            IConfiguration _config;
            void Run(IConfigurationSection section) {
                Foo.Use(_config["Jwt:Algorithm"]);
                Foo.Use(_config.GetValue<string>("Jwt:Alg", "RS256"));
                Foo.Use(_config.GetSection("Jwt")["Algorithm"]);
                Foo.Use(_config.GetSection("Jwt").GetSection("Inner").GetValue<string>("Name"));
                Foo.Use(_config.GetSection("Jwt:Algorithm").Value);
                Foo.Use(section["Direct"]);
            }
        }
        "#,
    );
    let key = |k: &str, d: Option<&str>| Some((k.to_owned(), d.map(str::to_owned)));
    assert_eq!(
        found,
        [
            key("Jwt:Algorithm", None),
            key("Jwt:Alg", Some("RS256")),
            key("Jwt:Algorithm", None),
            key("Jwt:Inner:Name", None),
            key("Jwt:Algorithm", None),
            key("Direct", None),
        ]
    );
}

#[test]
fn an_indexer_of_something_else_is_not_configuration() {
    let found = injected(
        r#"
        using System.Collections.Generic;
        class A {
            void Run(Dictionary<string, string> map, string[] list) {
                Foo.Use(map["Jwt:Algorithm"]);
                Foo.Use(list[0]);
            }
        }
        "#,
    );
    assert_eq!(found, [None, None]);
}

/// What the file binds: each type and the section it is bound to (`None`
/// when the section is not a literal).
fn bindings(source: &str) -> Vec<(String, Option<String>)> {
    lower(source)
        .facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Bind { ty, section } => Some((
                ty.name.clone(),
                match &section.value {
                    ArgValue::Str(text) => Some(text.clone()),
                    _ => None,
                },
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn the_options_pattern_binds_a_type_to_a_section() {
    let found = bindings(
        r#"
        using Microsoft.Extensions.Configuration;
        class A {
            void Run(IConfiguration config, IServiceCollection services) {
                services.Configure<JwtOptions>(config.GetSection("Jwt"));
                services.Configure<NamedOptions>("name", config.GetSection("A").GetSection("B"));
                var got = config.GetSection("Got").Get<GotOptions>();
                var bound = new BoundOptions();
                config.GetSection("Bound").Bind(bound);
                services.AddOptions<ChainOptions>().Bind(config.GetSection("Chain")).ValidateOnStart();
                services.AddOptions<PathOptions>().BindConfiguration("Path");
            }
        }
        "#,
    );
    let named = |ty: &str, section: &str| (ty.to_owned(), Some(section.to_owned()));
    assert_eq!(
        found,
        [
            named("JwtOptions", "Jwt"),
            named("NamedOptions", "A:B"),
            named("GotOptions", "Got"),
            named("BoundOptions", "Bound"),
            named("ChainOptions", "Chain"),
            named("PathOptions", "Path"),
        ]
    );
}

#[test]
fn a_section_named_by_a_constant_stays_an_argument() {
    let unit = lower(
        r#"
        class A { void Run(IConfiguration config, IServiceCollection services) {
            services.Configure<JwtOptions>(config.GetSection(JwtOptions.SectionName));
        } }
        "#,
    );
    let sections: Vec<_> = unit
        .facts()
        .iter()
        .filter_map(|f| match &f.kind {
            FactKind::Bind { section, .. } => Some(section.raw.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(sections, ["JwtOptions.SectionName"]);
}

#[test]
fn what_is_not_the_configuration_binds_nothing() {
    let found = bindings(
        r#"
        class A {
            void Run(Cache cache, IServiceCollection services, Thing thing) {
                cache.GetSection("x").Get<Entry>();
                var plain = cache.Get<Entry>();
                services.Configure<JwtOptions>(o => o.Algorithm = "RS256");
                thing.Bind(plain);
            }
        }
        "#,
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn an_options_wrapper_reads_through_value_to_its_type() {
    let unit = lower(
        r#"
        class Service {
            private readonly IOptions<JwtOptions> _options;
            Service(IOptionsMonitor<JwtOptions> monitor) { }
            void Run() {
                Foo.Use(_options.Value.Algorithm);
            }
        }
        "#,
    );
    let owners: Vec<_> = calls(&unit)
        .into_iter()
        .filter(|c| c.1 == "Use")
        .flat_map(|c| c.2)
        .flat_map(|v| match v {
            ArgValue::OneOf(candidates) => candidates.into_iter().map(|c| c.value).collect(),
            other => vec![other],
        })
        .filter_map(|v| match v {
            ArgValue::Returns { owner, method, .. } => Some((owner.name, method)),
            _ => None,
        })
        .collect();
    assert_eq!(owners, [("JwtOptions".to_owned(), "Algorithm".to_owned())]);
}

#[test]
fn a_settable_property_is_bound_and_keeps_its_initializer_as_default() {
    let unit = lower(
        r#"
        namespace Acme;
        public class JwtOptions {
            public string Algorithm { get; set; } = "HS256";
            public string Issuer { get; set; }
            public string Fixed { get; } = "RS256";
        }
        "#,
    );
    let bound: Vec<_> = unit
        .methods()
        .iter()
        .filter_map(|m| {
            let candidate = m.returns.iter().find_map(|c| match &c.value {
                ArgValue::Bound {
                    property, default, ..
                } => Some((property.clone(), default.clone())),
                _ => None,
            })?;
            Some((m.name.clone(), candidate))
        })
        .collect();
    assert!(
        bound.contains(&(
            "Algorithm".into(),
            ("Algorithm".into(), Some("HS256".into()))
        )),
        "{bound:?}"
    );
    assert!(
        bound.contains(&("Issuer".into(), ("Issuer".into(), None))),
        "{bound:?}"
    );
    // Nothing can set `Fixed`: it is its literal, not a bound value.
    assert!(!bound.iter().any(|b| b.0 == "Fixed"), "{bound:?}");
}
