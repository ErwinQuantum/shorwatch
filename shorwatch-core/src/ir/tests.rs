use super::*;

#[test]
fn type_ref_matches_by_qualified_name_when_known() {
    assert!(TypeRef::qualified("javax.crypto.Cipher").is("javax.crypto.Cipher"));
    assert!(!TypeRef::qualified("com.acme.Cipher").is("javax.crypto.Cipher"));
}

#[test]
fn type_ref_falls_back_to_simple_name() {
    assert!(TypeRef::simple("Cipher").is("javax.crypto.Cipher"));
    assert!(!TypeRef::simple("Signature").is("javax.crypto.Cipher"));
}

#[test]
fn nested_types_need_their_outer_type_to_match() {
    let wanted = "com.nimbusds.jose.jwk.ECKey.Builder";
    assert!(TypeRef::simple("ECKey.Builder").is(wanted));
    // Found in the wild: every other class's `Builder`.
    assert!(!TypeRef::simple("Builder").is(wanted));
    assert!(!TypeRef::simple("GroupMetadataManagerTestContext.Builder").is(wanted));
    assert!(!TypeRef::simple("SIG").is("io.jsonwebtoken.Jwts.SIG"));
    assert!(TypeRef::simple("Jwts.SIG").is("io.jsonwebtoken.Jwts.SIG"));
}

#[test]
fn enclosing_walks_up_to_requested_kind() {
    let mut unit = SourceUnit::new("A.java", Language::Java);
    let class = unit.add_scope(ScopeKind::Type, Some("A".into()), SourceUnit::ROOT);
    let method = unit.add_scope(ScopeKind::Method, Some("run".into()), class);

    assert_eq!(unit.enclosing(method, ScopeKind::Type), class);
    assert_eq!(unit.enclosing(method, ScopeKind::Method), method);
    assert_eq!(unit.enclosing(method, ScopeKind::File), SourceUnit::ROOT);
    assert_eq!(
        unit.enclosing(SourceUnit::ROOT, ScopeKind::Type),
        SourceUnit::ROOT
    );
}

#[test]
fn is_within_follows_parents() {
    let mut unit = SourceUnit::new("A.java", Language::Java);
    let a = unit.add_scope(ScopeKind::Type, Some("A".into()), SourceUnit::ROOT);
    let b = unit.add_scope(ScopeKind::Type, Some("B".into()), SourceUnit::ROOT);
    let m = unit.add_scope(ScopeKind::Method, None, a);

    assert!(unit.is_within(m, a));
    assert!(unit.is_within(m, SourceUnit::ROOT));
    assert!(!unit.is_within(m, b));
}

#[test]
fn unimported_names_only_match_types_of_their_possible_packages() {
    let packages = vec!["org.keycloak.crypto".to_owned(), "java.lang".to_owned()];
    let key_type = TypeRef::in_packages("KeyType", packages);
    assert!(key_type.is("org.keycloak.crypto.KeyType"));
    assert!(!key_type.is("com.azure.security.keyvault.keys.models.KeyType"));
    let system = TypeRef::in_packages(
        "System",
        vec!["com.acme".to_owned(), "java.lang".to_owned()],
    );
    assert!(system.is("java.lang.System"));
}
