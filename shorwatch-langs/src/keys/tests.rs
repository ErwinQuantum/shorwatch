use super::*;

/// The fixtures the rule tests also use, generated with OpenSSL, keytool and
/// ssh-keygen.
macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            "../../../shorwatch-rules/tests/fixtures/keys/",
            $name
        ))
    };
}

/// `(line, label)` of every key fact, and whether the text was kept.
fn keys(name: &str, bytes: &[u8]) -> (Vec<(u32, String)>, bool) {
    let (unit, text) = KeyMaterialFrontend
        .lower_bytes(name, bytes.to_vec())
        .unwrap();
    let keys = unit
        .facts()
        .iter()
        .map(|f| match &f.kind {
            FactKind::Key { label, .. } => (f.location.start.line, label.clone()),
            other => panic!("{other:?}"),
        })
        .collect();
    (keys, text.is_some())
}

fn labels(name: &str, bytes: &[u8]) -> Vec<String> {
    keys(name, bytes).0.into_iter().map(|(_, l)| l).collect()
}

#[test]
fn pem_certificates_name_their_key_signature_and_expiry() {
    let (keys, text) = keys("server.pem", fixture!("server.pem"));
    assert!(text);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, 1);
    let label = &keys[0].1;
    assert!(
        label.starts_with(
            "certificate \"CN=api.example.com, O=Example\": RSA 2048-bit, self-signed with SHA256withRSA, valid until 20"
        ),
        "{label}"
    );

    let legacy = labels("legacy-sha1.crt", fixture!("legacy-sha1.crt"));
    assert!(
        legacy[0].contains("RSA 1024-bit, signed with SHA1withRSA"),
        "{legacy:?}"
    );
    let ed = labels("signer-ed25519.pem", fixture!("signer-ed25519.pem"));
    assert!(
        ed[0].contains(": Ed25519, self-signed with Ed25519"),
        "{ed:?}"
    );
}

#[test]
fn public_and_private_keys_in_every_pem_form() {
    assert_eq!(
        labels("x.pem", fixture!("agreement-x25519.pub.pem")),
        ["public key: X25519"]
    );
    assert_eq!(
        labels("dsa.pem", fixture!("dsa-public.pem")),
        ["public key: DSA 2048-bit"]
    );
    assert_eq!(
        labels("dh.pem", fixture!("dh-public.pem")),
        ["public key: DH"]
    );
    // PKCS#1, after a comment line; PKCS#8.
    let (rsa, _) = keys("legacy-rsa.key", fixture!("legacy-rsa.key"));
    assert_eq!(rsa, [(2, "private key: RSA 1024-bit".to_owned())]);
    assert_eq!(
        labels("ec.key", fixture!("client-ec.key")),
        ["private key: EC secp256r1"]
    );
    assert_eq!(
        labels("ops.key", fixture!("ops_ed25519.key")),
        ["SSH private key: Ed25519"]
    );
    // The algorithm of an encrypted key is not visible.
    assert!(labels("enc.key", fixture!("encrypted.key")).is_empty());
}

/// Reports show the text of key files: private keys never reach them.
#[test]
fn private_keys_are_redacted_from_the_text_reports_show() {
    for name in [
        "legacy-rsa.key",
        "client-ec.key",
        "ops_ed25519.key",
        "encrypted.key",
    ] {
        let bytes = match name {
            "legacy-rsa.key" => &fixture!("legacy-rsa.key")[..],
            "client-ec.key" => &fixture!("client-ec.key")[..],
            "ops_ed25519.key" => &fixture!("ops_ed25519.key")[..],
            _ => &fixture!("encrypted.key")[..],
        };
        let original = String::from_utf8(bytes.to_vec()).unwrap();
        let (_, text) = KeyMaterialFrontend
            .lower_bytes(name, bytes.to_vec())
            .unwrap();
        let text = text.unwrap();
        assert_eq!(text.lines().count(), original.lines().count(), "{name}");
        for line in original
            .lines()
            .filter(|l| l.len() > 40 && !l.contains(' '))
        {
            assert!(!text.contains(line), "{name} still shows {line}");
        }
        assert!(text.contains("PRIVATE KEY-----"), "{name}: markers stay");
    }
    // Public keys and certificates are public: they stay.
    let server = String::from_utf8(fixture!("server.pem").to_vec()).unwrap();
    let (_, text) = KeyMaterialFrontend
        .lower_bytes("server.pem", server.clone().into_bytes())
        .unwrap();
    assert_eq!(text.unwrap(), server);
}

#[test]
fn der_certificates_and_keystores_have_no_text() {
    let (keys, text) = keys("client.der", fixture!("client.der"));
    assert!(!text);
    assert_eq!(keys.len(), 1);
    assert!(
        keys[0].1.starts_with(
            "certificate \"CN=client.example.com\": EC secp256r1, self-signed with SHA256withECDSA"
        ),
        "{keys:?}"
    );

    let jks = labels("truststore.jks", fixture!("truststore.jks"));
    assert_eq!(jks.len(), 2, "{jks:?}");
    assert!(
        jks.iter()
            .any(|l| l.contains("(alias \"api\"): RSA 2048-bit")),
        "{jks:?}"
    );
    assert!(
        jks.iter()
            .any(|l| l.contains("(alias \"client\"): EC secp256r1")),
        "{jks:?}"
    );

    let clear = labels("client-clear.p12", fixture!("client-clear.p12"));
    // The private key is its certificate's: one finding, not two.
    assert_eq!(clear.len(), 1, "{clear:?}");
    assert!(
        clear[0].contains("(alias \"client\"): EC secp256r1"),
        "{clear:?}"
    );
    // Certificates encrypted with the store's password stay unknown.
    assert!(labels("server.p12", fixture!("server-encrypted.p12")).is_empty());
}

#[test]
fn ssh_public_key_lines() {
    let (found, _) = keys("authorized.pub", fixture!("authorized.pub"));
    assert_eq!(
        found,
        [
            (
                1,
                "SSH public key \"ci@example\": ECDSA secp256r1".to_owned()
            ),
            (2, "SSH public key \"ops@example\": Ed25519".to_owned()),
        ]
    );
    assert_eq!(
        labels("deploy_rsa.pub", fixture!("deploy_rsa.pub")),
        ["SSH public key \"deploy@example\": RSA 3072-bit"]
    );
    // `ssh-dss` is DSA, fixed at 1024 bits.
    assert_eq!(
        labels("legacy_dss.pub", fixture!("legacy-dss.pub")),
        ["SSH public key \"legacy@example\": DSA 1024-bit"]
    );
    // Options before the type, as in authorized_keys.
    let line = std::str::from_utf8(fixture!("deploy_rsa.pub")).unwrap();
    let with_options = format!("from=\"10.0.0.0/8\",no-pty {line}");
    let (found, _) = keys("authorized_keys", with_options.as_bytes());
    assert_eq!(found.len(), 1);
}

#[test]
fn post_quantum_keys_are_named() {
    let algorithms: Vec<_> = KeyMaterialFrontend
        .lower_bytes("Clean.pem", fixture!("Clean.pem").to_vec())
        .unwrap()
        .0
        .facts()
        .iter()
        .map(|f| match &f.kind {
            FactKind::Key {
                algorithm,
                signature,
                ..
            } => (algorithm.clone(), signature.clone()),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(
        algorithms,
        [
            ("ML-DSA-65".to_owned(), None),
            ("ML-KEM-768".to_owned(), None),
        ]
    );
}

#[test]
fn files_that_are_not_key_material_give_nothing() {
    for bytes in [
        &b"just some text\n"[..],
        b"\x30\x03\x02\x01",
        b"\xFE\xED\xFE\xED\x00",
    ] {
        assert!(labels("x.key", bytes).is_empty());
    }
}

#[test]
fn der_helpers() {
    assert_eq!(
        der::oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]).as_deref(),
        Some("1.2.840.113549.1.1.1")
    );
    assert_eq!(
        der::oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]).as_deref(),
        Some("2.16.840.1.101.3.4.3.18")
    );
    assert_eq!(der::bit_length(&[0x00, 0x80, 0x00]), Some(16));
    assert_eq!(der::bit_length(&[0x01]), Some(1));
    assert_eq!(pem::base64("TWFu\nTWE=").as_deref(), Some(&b"ManMa"[..]));
    assert_eq!(pem::base64("not base64!"), None);
}

/// A JKS truststore of trusted certificates, assembled by hand.
fn truststore(certificates: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = vec![0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2];
    out.extend(u32::try_from(certificates.len()).unwrap().to_be_bytes());
    let utf = |out: &mut Vec<u8>, s: &str| {
        out.extend(u16::try_from(s.len()).unwrap().to_be_bytes());
        out.extend(s.as_bytes());
    };
    for (alias, der) in certificates {
        out.extend(2u32.to_be_bytes());
        utf(&mut out, alias);
        out.extend([0; 8]);
        utf(&mut out, "X.509");
        out.extend(u32::try_from(der.len()).unwrap().to_be_bytes());
        out.extend(*der);
    }
    out
}

#[test]
fn truststores_group_the_certificates_they_only_trust() {
    let text = std::str::from_utf8(fixture!("server.pem")).unwrap();
    let rsa = pem::blocks(text).remove(0).der;
    let ec: &[u8] = fixture!("client.der");
    let store = truststore(&[
        ("a", &rsa),
        ("b", &rsa),
        ("c", ec),
        ("d", &rsa),
        ("e", &rsa),
    ]);
    assert_eq!(
        labels("cacerts.jks", &store),
        [
            "4 trusted certificates: RSA (\"CN=api.example.com, O=Example\", \"CN=api.example.com, O=Example\", \"CN=api.example.com, O=Example\", ...)",
            "certificate \"CN=client.example.com\" (alias \"c\"): EC secp256r1, self-signed with SHA256withECDSA, valid until 2036-10-24",
        ]
    );
}
