//! X.509 certificates and requests, public keys (SPKI) and private keys
//! (PKCS#8, PKCS#1, SEC 1): the public key algorithm, its size or curve,
//! and how a certificate is signed.

use super::der::{
    self, BIT_STRING, CONTEXT_0, Der, GENERALIZED_TIME, INTEGER, OCTET_STRING, OID, SEQUENCE, SET,
    UTC_TIME,
};

/// What a key is, as far as quantum risk goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct KeyInfo {
    pub(super) algorithm: String,
    pub(super) bits: Option<u32>,
    pub(super) curve: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Certificate {
    pub(super) key: KeyInfo,
    pub(super) signature: String,
    pub(super) subject: String,
    /// `YYYY-MM-DD`.
    pub(super) not_after: Option<String>,
    /// Issued by its own subject: a root CA or a pinned certificate, whose
    /// signature nobody relies on.
    pub(super) self_signed: bool,
}

/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`.
pub(super) fn certificate(bytes: &[u8]) -> Option<Certificate> {
    let mut outer = Der::new(bytes).nested(SEQUENCE)?;
    let mut tbs = outer.nested(SEQUENCE)?;
    let signature = algorithm_id(&mut outer)?.0;
    tbs.skip_optional(CONTEXT_0); // version
    tbs.expect(INTEGER)?; // serial
    tbs.expect(SEQUENCE)?; // signature, repeated
    let issuer = tbs.expect(SEQUENCE)?;
    let mut validity = tbs.nested(SEQUENCE)?;
    validity.next()?;
    let not_after = validity.next().and_then(|t| date(t.tag, t.content));
    let subject = tbs.expect(SEQUENCE)?;
    let key = public_key(tbs.expect(SEQUENCE)?)?;
    Some(Certificate {
        key,
        signature: signature_name(&signature),
        subject: name(subject),
        not_after,
        self_signed: issuer == subject,
    })
}

/// A PKCS#10 request: `SEQUENCE { info { version, subject, spki, .. }, alg, sig }`.
pub(super) fn request(bytes: &[u8]) -> Option<(KeyInfo, String, String)> {
    let mut outer = Der::new(bytes).nested(SEQUENCE)?;
    let mut info = outer.nested(SEQUENCE)?;
    let signature = algorithm_id(&mut outer)?.0;
    info.expect(INTEGER)?;
    let subject = name(info.expect(SEQUENCE)?);
    let key = public_key(info.expect(SEQUENCE)?)?;
    Some((key, signature_name(&signature), subject))
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }`,
/// given its content.
pub(super) fn public_key(spki: &[u8]) -> Option<KeyInfo> {
    let mut spki = Der::new(spki);
    let (oid, params) = algorithm_id(&mut spki)?;
    let key = spki.expect(BIT_STRING)?.get(1..)?;
    let bits = match oid.as_str() {
        RSA | RSA_PSS => rsa_public_bits(key),
        _ => None,
    };
    Some(key_info(&oid, params, bits))
}

/// `PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey, .. }`.
pub(super) fn private_key(bytes: &[u8]) -> Option<KeyInfo> {
    private_key_info(Der::new(bytes).nested(SEQUENCE)?)
}

/// [`private_key`], given the sequence's content.
pub(super) fn private_key_info(mut info: Der<'_>) -> Option<KeyInfo> {
    info.expect(INTEGER)?;
    let (oid, params) = algorithm_id(&mut info)?;
    let key = info.expect(OCTET_STRING)?;
    let bits = match oid.as_str() {
        RSA | RSA_PSS => rsa_private_bits(key),
        _ => None,
    };
    Some(key_info(&oid, params, bits))
}

/// PKCS#1 `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`.
pub(super) fn rsa_public_bits(bytes: &[u8]) -> Option<u32> {
    let mut key = Der::new(bytes).nested(SEQUENCE)?;
    der::bit_length(key.expect(INTEGER)?)
}

/// PKCS#1 `RSAPrivateKey ::= SEQUENCE { version, modulus, .. }`.
pub(super) fn rsa_private_bits(bytes: &[u8]) -> Option<u32> {
    let mut key = Der::new(bytes).nested(SEQUENCE)?;
    key.expect(INTEGER)?;
    der::bit_length(key.expect(INTEGER)?)
}

/// SEC 1 `ECPrivateKey ::= SEQUENCE { version, privateKey, [0] parameters, .. }`.
pub(super) fn ec_private_curve(bytes: &[u8]) -> Option<KeyInfo> {
    let mut key = Der::new(bytes).nested(SEQUENCE)?;
    key.expect(INTEGER)?;
    key.expect(OCTET_STRING)?;
    let curve = key
        .nested(CONTEXT_0)
        .and_then(|mut p| p.expect(OID))
        .and_then(der::oid);
    Some(KeyInfo {
        algorithm: "EC".into(),
        bits: None,
        curve: curve.map(|c| curve_name(&c)),
    })
}

/// OpenSSL's traditional `DSAPrivateKey ::= SEQUENCE { version, p, q, g, y, x }`.
pub(super) fn dsa_private_bits(bytes: &[u8]) -> Option<u32> {
    let mut key = Der::new(bytes).nested(SEQUENCE)?;
    key.expect(INTEGER)?;
    der::bit_length(key.expect(INTEGER)?)
}

const RSA: &str = "1.2.840.113549.1.1.1";
const RSA_PSS: &str = "1.2.840.113549.1.1.10";
const EC: &str = "1.2.840.10045.2.1";
const DSA: &str = "1.2.840.10040.4.1";

fn key_info(oid: &str, params: Option<der::Tlv<'_>>, bits: Option<u32>) -> KeyInfo {
    let (algorithm, bits, curve) = match oid {
        RSA | RSA_PSS => ("RSA", bits, None),
        EC => {
            let curve = params
                .filter(|p| p.tag == OID)
                .and_then(|p| der::oid(p.content))
                .map(|c| curve_name(&c));
            ("EC", None, curve)
        }
        // `Dss-Parms ::= SEQUENCE { p, q, g }`: the size is p's.
        DSA => {
            let bits = params
                .filter(|p| p.tag == SEQUENCE)
                .and_then(|p| Der::new(p.content).expect(INTEGER))
                .and_then(der::bit_length);
            ("DSA", bits, None)
        }
        "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => ("DH", None, None),
        "1.3.101.110" => ("X25519", None, None),
        "1.3.101.111" => ("X448", None, None),
        "1.3.101.112" => ("Ed25519", None, None),
        "1.3.101.113" => ("Ed448", None, None),
        "2.16.840.1.101.3.4.3.17" => ("ML-DSA-44", None, None),
        "2.16.840.1.101.3.4.3.18" => ("ML-DSA-65", None, None),
        "2.16.840.1.101.3.4.3.19" => ("ML-DSA-87", None, None),
        "2.16.840.1.101.3.4.4.1" => ("ML-KEM-512", None, None),
        "2.16.840.1.101.3.4.4.2" => ("ML-KEM-768", None, None),
        "2.16.840.1.101.3.4.4.3" => ("ML-KEM-1024", None, None),
        _ if is_slh_dsa(oid) => ("SLH-DSA", None, None),
        other => {
            return KeyInfo {
                algorithm: other.to_owned(),
                bits: None,
                curve: None,
            };
        }
    };
    KeyInfo {
        algorithm: algorithm.to_owned(),
        bits,
        curve,
    }
}

/// `2.16.840.1.101.3.4.3.20` to `.31`, FIPS 205.
fn is_slh_dsa(oid: &str) -> bool {
    oid.strip_prefix("2.16.840.1.101.3.4.3.")
        .and_then(|arc| arc.parse::<u8>().ok())
        .is_some_and(|arc| (20..=31).contains(&arc))
}

fn curve_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.3.1.7" => "secp256r1",
        "1.3.132.0.34" => "secp384r1",
        "1.3.132.0.35" => "secp521r1",
        "1.3.132.0.10" => "secp256k1",
        "1.2.840.10045.3.1.1" => "secp192r1",
        "1.3.132.0.33" => "secp224r1",
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1",
        other => other,
    }
    .to_owned()
}

/// Signature algorithms by their JCA names, which rules and people know.
fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "MD5withRSA",
        "1.2.840.113549.1.1.5" => "SHA1withRSA",
        "1.2.840.113549.1.1.14" => "SHA224withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        RSA_PSS => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "SHA1withECDSA",
        "1.2.840.10045.4.3.1" => "SHA224withECDSA",
        "1.2.840.10045.4.3.2" => "SHA256withECDSA",
        "1.2.840.10045.4.3.3" => "SHA384withECDSA",
        "1.2.840.10045.4.3.4" => "SHA512withECDSA",
        "1.2.840.10040.4.3" => "SHA1withDSA",
        "2.16.840.1.101.3.4.3.1" => "SHA224withDSA",
        "2.16.840.1.101.3.4.3.2" => "SHA256withDSA",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        _ if is_slh_dsa(oid) => "SLH-DSA",
        other => other,
    }
    .to_owned()
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.
fn algorithm_id<'a>(der: &mut Der<'a>) -> Option<(String, Option<der::Tlv<'a>>)> {
    let mut id = der.nested(SEQUENCE)?;
    let oid = der::oid(id.expect(OID)?)?;
    Some((oid, id.next()))
}

/// A distinguished name as `CN=api.example.com, O=Example`: the common name
/// first, then the rest as written.
fn name(content: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut rdns = Der::new(content);
    while let Some(mut rdn) = rdns.nested(SET) {
        while let Some(mut attribute) = rdn.nested(SEQUENCE) {
            let Some(oid) = attribute.expect(OID).and_then(der::oid) else {
                continue;
            };
            let Some(value) = attribute.next() else {
                continue;
            };
            let key = match oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.6" => "C",
                _ => continue,
            };
            parts.push(format!("{key}={}", String::from_utf8_lossy(value.content)));
        }
    }
    parts.sort_by_key(|part| !part.starts_with("CN="));
    parts.join(", ")
}

/// `UTCTime` (`YYMMDD...`) or `GeneralizedTime` (`YYYYMMDD...`) as a date.
fn date(tag: u8, content: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?;
    let digits = text
        .get(..8)
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit()));
    let (year, rest) = match tag {
        UTC_TIME => {
            let yy: u32 = text.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, text.get(2..6)?)
        }
        GENERALIZED_TIME => (digits?.get(..4)?.parse().ok()?, digits?.get(4..8)?),
        _ => return None,
    };
    Some(format!("{year}-{}-{}", &rest[..2], &rest[2..4]))
}
