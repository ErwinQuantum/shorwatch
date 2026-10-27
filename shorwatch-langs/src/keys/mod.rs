//! Key material: the algorithm of keys and certificates themselves. A
//! repository's `server.pem`, `truststore.jks` or `deploy_rsa.pub` is as
//! quantum-vulnerable as the code that uses it, and lives as long.
//!
//! Formats are told apart by content, not by extension: PEM blocks (X.509
//! certificates and requests, SPKI, PKCS#8, PKCS#1, SEC 1, OpenSSH), DER
//! certificates, keys and PKCS#12 files, JKS/JCEKS keystores and SSH public
//! key lines. Encrypted content (a password-protected private key, the
//! encrypted parts of a PKCS#12) is skipped: its algorithm is not visible.

use std::fmt::Write as _;

use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, Location, SourceUnit};

use crate::span::byte_range;
use crate::{Frontend, LangError, decode};
use keystore::Entry;
use x509::KeyInfo;

mod der;
mod keystore;
mod pem;
mod ssh;
#[cfg(test)]
mod tests;
mod x509;

#[derive(Debug, Clone, Copy, Default)]
pub struct KeyMaterialFrontend;

impl Frontend for KeyMaterialFrontend {
    fn language(&self) -> Language {
        Language::KeyMaterial
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[
            "pem",
            "crt",
            "cer",
            "der",
            "key",
            "pub",
            "csr",
            "p7b",
            "jks",
            "jceks",
            "keystore",
            "truststore",
            "p12",
            "pfx",
        ]
    }

    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError> {
        Ok(self.lower_bytes(path, source.as_bytes().to_vec())?.0)
    }

    /// Text formats (PEM, SSH public keys) keep their text for reports,
    /// private keys redacted; binary ones have no lines to show.
    fn lower_bytes(
        &self,
        path: &str,
        bytes: Vec<u8>,
    ) -> Result<(SourceUnit, Option<String>), LangError> {
        let mut unit = SourceUnit::new(path, Language::KeyMaterial);
        if keystore::is_java_keystore(&bytes) {
            entries(&mut unit, keystore::java_keystore(&bytes), "keystore entry");
            return Ok((unit, None));
        }
        if bytes.first() == Some(&0x30) {
            binary(&mut unit, &bytes);
            return Ok((unit, None));
        }
        let text = decode(bytes);
        let blocks = pem::blocks(&text);
        if blocks.is_empty() {
            ssh_public_keys(&mut unit, &text);
        }
        for block in blocks {
            let location = byte_range(&text, block.start, block.end);
            if let Some((key, label)) = pem_block(block.label, &block.der) {
                push(&mut unit, key, label, location);
            }
        }
        Ok((unit, Some(pem::redact_private_keys(&text))))
    }
}

/// What a key fact says besides the key itself.
struct Label {
    what: String,
    signature: Option<String>,
    self_signed: bool,
    not_after: Option<String>,
}

impl Label {
    fn plain(what: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            signature: None,
            self_signed: false,
            not_after: None,
        }
    }

    fn certificate(certificate: &x509::Certificate, alias: Option<&str>) -> Self {
        let mut what = format!("certificate \"{}\"", certificate.subject);
        if let Some(alias) = alias {
            let _ = write!(what, " (alias \"{alias}\")");
        }
        Self {
            what,
            signature: Some(certificate.signature.clone()),
            self_signed: certificate.self_signed,
            not_after: certificate.not_after.clone(),
        }
    }
}

fn push(unit: &mut SourceUnit, key: KeyInfo, label: Label, location: Location) {
    let mut text = format!("{}: {}", label.what, key.algorithm);
    if let Some(bits) = key.bits {
        let _ = write!(text, " {bits}-bit");
    }
    if let Some(curve) = &key.curve {
        let _ = write!(text, " {curve}");
    }
    if let Some(signature) = &label.signature {
        let how = if label.self_signed {
            "self-signed"
        } else {
            "signed"
        };
        let _ = write!(text, ", {how} with {signature}");
    }
    if let Some(date) = &label.not_after {
        let _ = write!(text, ", valid until {date}");
    }
    let kind = FactKind::Key {
        algorithm: key.algorithm,
        bits: key.bits,
        curve: key.curve,
        // Nobody verifies a self-signed certificate's signature: trust
        // comes from the certificate itself, so its hash does not matter.
        signature: label.signature.filter(|_| !label.self_signed),
        label: text,
    };
    unit.push(kind, SourceUnit::ROOT, location);
}

fn pem_block(label: &str, der: &[u8]) -> Option<(KeyInfo, Label)> {
    let plain = |key: Option<KeyInfo>, what: &str| Some((key?, Label::plain(what)));
    match label {
        "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
            let certificate = x509::certificate(der)?;
            let label = Label::certificate(&certificate, None);
            Some((certificate.key, label))
        }
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
            let (key, signature, subject) = x509::request(der)?;
            // Signed with its own key, only to prove possession of it.
            let label = Label {
                what: format!("certificate request \"{subject}\""),
                signature: Some(signature),
                self_signed: true,
                not_after: None,
            };
            Some((key, label))
        }
        "PUBLIC KEY" => {
            let spki = der::Der::new(der).expect(der::SEQUENCE)?;
            plain(x509::public_key(spki), "public key")
        }
        "PRIVATE KEY" => plain(x509::private_key(der), "private key"),
        "RSA PUBLIC KEY" => plain(rsa(x509::rsa_public_bits(der)), "public key"),
        "RSA PRIVATE KEY" => plain(rsa(x509::rsa_private_bits(der)), "private key"),
        "EC PRIVATE KEY" => plain(x509::ec_private_curve(der), "private key"),
        "DSA PRIVATE KEY" => {
            let key = x509::dsa_private_bits(der).map(|bits| KeyInfo {
                algorithm: "DSA".into(),
                bits: Some(bits),
                curve: None,
            });
            plain(key, "private key")
        }
        "OPENSSH PRIVATE KEY" => plain(ssh::private_key_file(der), "SSH private key"),
        _ => None,
    }
}

fn rsa(bits: Option<u32>) -> Option<KeyInfo> {
    Some(KeyInfo {
        algorithm: "RSA".into(),
        bits: Some(bits?),
        curve: None,
    })
}

/// A DER file: a certificate, a PKCS#12, a public or a private key.
fn binary(unit: &mut SourceUnit, bytes: &[u8]) {
    if let Some(certificate) = x509::certificate(bytes) {
        let label = Label::certificate(&certificate, None);
        push(unit, certificate.key, label, whole_file());
    } else if let Some(entries_) = keystore::pkcs12(bytes) {
        entries(unit, entries_, "PKCS#12 entry");
    } else if let Some(key) = der::Der::new(bytes)
        .expect(der::SEQUENCE)
        .and_then(x509::public_key)
    {
        push(unit, key, Label::plain("public key"), whole_file());
    } else if let Some(key) = x509::private_key(bytes) {
        push(unit, key, Label::plain("private key"), whole_file());
    }
}

fn entries(unit: &mut SourceUnit, entries: Vec<Entry<'_>>, kind: &str) {
    // A key and its certificate are one key: the certificate says more.
    let certified: Vec<Option<String>> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Certificate { alias, .. } => Some(alias.clone()),
            Entry::PrivateKey { .. } => None,
        })
        .collect();
    // A truststore often copies a JDK's hundreds of CAs: certificates the
    // store only trusts are grouped by algorithm, one fact per group, so
    // they do not drown the store's own keys.
    let trusted: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Certificate {
                der, trusted: true, ..
            } => x509::certificate(der),
            _ => None,
        })
        .collect();
    let crowded = |algorithm: &str| {
        trusted
            .iter()
            .filter(|c| c.key.algorithm == algorithm)
            .nth(1)
            .is_some()
    };
    let mut grouped: Vec<String> = Vec::new();
    for entry in entries {
        match entry {
            Entry::Certificate {
                alias,
                der,
                trusted: only_trusted,
            } => {
                let Some(certificate) = x509::certificate(der) else {
                    continue;
                };
                let algorithm = certificate.key.algorithm.clone();
                if !only_trusted || !crowded(&algorithm) {
                    let label = Label::certificate(&certificate, alias.as_deref());
                    push(unit, certificate.key, label, whole_file());
                } else if !grouped.contains(&algorithm) {
                    trusted_group(unit, &trusted, &algorithm);
                    grouped.push(algorithm);
                }
            }
            Entry::PrivateKey { alias, .. } if alias.is_some() && certified.contains(&alias) => {}
            Entry::PrivateKey { alias, key } => {
                let what = match alias {
                    Some(alias) => format!("{kind} \"{alias}\", private key"),
                    None => format!("{kind}, private key"),
                };
                push(unit, key, Label::plain(what), whole_file());
            }
        }
    }
}

/// `251 trusted certificates: RSA ("CN=A", "CN=B", "CN=C", ...)`.
fn trusted_group(unit: &mut SourceUnit, trusted: &[x509::Certificate], algorithm: &str) {
    let group: Vec<_> = trusted
        .iter()
        .filter(|c| c.key.algorithm == algorithm)
        .collect();
    let mut examples: Vec<String> = group
        .iter()
        .take(3)
        .map(|c| format!("\"{}\"", c.subject))
        .collect();
    if group.len() > 3 {
        examples.push("...".into());
    }
    let kind = FactKind::Key {
        algorithm: algorithm.to_owned(),
        bits: None,
        curve: None,
        signature: None,
        label: format!(
            "{} trusted certificates: {algorithm} ({})",
            group.len(),
            examples.join(", ")
        ),
    };
    unit.push(kind, SourceUnit::ROOT, whole_file());
}

/// Binary files have no lines: findings point at the file.
fn whole_file() -> Location {
    Location::line(1, 1, 1)
}

/// `ssh-rsa AAAA... comment` lines, as in `id_rsa.pub` or `authorized_keys`.
fn ssh_public_keys(unit: &mut SourceUnit, text: &str) {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let content = line.trim_end();
        if content.starts_with('#') {
            continue;
        }
        if let Some(key) = ssh::public_key_line(content) {
            let what = match key.comment {
                Some(comment) => format!("SSH public key \"{comment}\""),
                None => "SSH public key".to_owned(),
            };
            let location = byte_range(text, start + key.start, start + key.end);
            push(unit, key.key, Label::plain(what), location);
        }
    }
}
