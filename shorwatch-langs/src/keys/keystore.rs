//! Java keystores (JKS, JCEKS) and PKCS#12 files. Certificates in a JKS are
//! stored in the clear; a PKCS#12 usually encrypts them with the store's
//! password, and only its unencrypted parts can be read.

use super::der::{self, CONTEXT_0, Der, INTEGER, OCTET_STRING, OID, SEQUENCE, SET};
use super::x509::{self, KeyInfo};

/// What a keystore holds, by entry.
#[derive(Debug)]
pub(super) enum Entry<'a> {
    /// A DER certificate; `trusted` when it stands alone (a CA the store
    /// trusts), not as the certificate of one of the store's keys.
    Certificate {
        alias: Option<String>,
        der: &'a [u8],
        trusted: bool,
    },
    /// An unencrypted private key.
    PrivateKey { alias: Option<String>, key: KeyInfo },
}

const JKS: u32 = 0xFEED_FEED;
const JCEKS: u32 = 0xCECE_CECE;

pub(super) fn is_java_keystore(bytes: &[u8]) -> bool {
    bytes
        .get(..4)
        .is_some_and(|m| matches!(u32::from_be_bytes([m[0], m[1], m[2], m[3]]), JKS | JCEKS))
}

/// The certificates of a JKS or JCEKS keystore: trusted certificates, and
/// the first certificate of each key entry's chain. Reading stops at a
/// JCEKS secret key entry, a serialized Java object of unknown length.
pub(super) fn java_keystore(bytes: &[u8]) -> Vec<Entry<'_>> {
    let mut entries = Vec::new();
    let mut r = Reader { bytes, at: 4 };
    let Some(version) = r.u32() else {
        return entries;
    };
    let count = r.u32().unwrap_or(0);
    for _ in 0..count {
        let Some(tag) = r.u32() else { break };
        let Some(alias) = r.utf() else { break };
        if r.take(8).is_none() {
            break; // timestamp
        }
        match tag {
            1 => {
                let Some(length) = r.u32() else { break };
                if r.take(length as usize).is_none() {
                    break; // the encrypted key
                }
                let Some(chain) = r.u32() else { break };
                for index in 0..chain {
                    let Some(der) = r.certificate(version) else {
                        return entries;
                    };
                    if index == 0 {
                        entries.push(Entry::Certificate {
                            alias: Some(alias.clone()),
                            der,
                            trusted: false,
                        });
                    }
                }
            }
            2 => {
                let Some(der) = r.certificate(version) else {
                    break;
                };
                entries.push(Entry::Certificate {
                    alias: Some(alias),
                    der,
                    trusted: true,
                });
            }
            _ => break,
        }
    }
    entries
}

struct Reader<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl<'b> Reader<'b> {
    fn take(&mut self, n: usize) -> Option<&'b [u8]> {
        let slice = self.bytes.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A certificate: its type (version 2 only), then its encoding.
    fn certificate(&mut self, version: u32) -> Option<&'b [u8]> {
        if version == 2 {
            self.utf()?;
        }
        let length = self.u32()? as usize;
        self.take(length)
    }

    /// Java's `writeUTF`: a 2-byte length, then modified UTF-8.
    fn utf(&mut self) -> Option<String> {
        let b = self.take(2)?;
        let length = usize::from(u16::from_be_bytes([b[0], b[1]]));
        Some(String::from_utf8_lossy(self.take(length)?).into_owned())
    }
}

const DATA: &str = "1.2.840.113549.1.7.1";
const KEY_BAG: &str = "1.2.840.113549.1.12.10.1.1";
const CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const X509_CERTIFICATE: &str = "1.2.840.113549.1.9.22.1";
const FRIENDLY_NAME: &str = "1.2.840.113549.1.9.20";
const LOCAL_KEY_ID: &str = "1.2.840.113549.1.9.21";

/// The readable entries of a PKCS#12 file, or `None` when it is not one.
/// `PFX ::= SEQUENCE { version 3, authSafe ContentInfo, macData OPTIONAL }`.
pub(super) fn pkcs12(bytes: &[u8]) -> Option<Vec<Entry<'_>>> {
    let mut pfx = Der::new(bytes).nested(SEQUENCE)?;
    if pfx.expect(INTEGER)? != [3] {
        return None;
    }
    let auth_safe = data(pfx.nested(SEQUENCE)?)?;
    let mut contents = Der::new(auth_safe).nested(SEQUENCE)?;
    let mut entries = Vec::new();
    // Encrypted ContentInfos (`encryptedData`) are skipped: no password.
    while let Some(info) = contents.nested(SEQUENCE) {
        let Some(safe) = data(info) else { continue };
        let Some(mut bags) = Der::new(safe).nested(SEQUENCE) else {
            continue;
        };
        while let Some(bag) = bags.nested(SEQUENCE) {
            if let Some(entry) = safe_bag(bag) {
                entries.push(entry);
            }
        }
    }
    Some(entries)
}

/// The content of a `ContentInfo` of type `data`: `[0] OCTET STRING`.
fn data(mut info: Der<'_>) -> Option<&[u8]> {
    let oid = der::oid(info.expect(OID)?)?;
    (oid == DATA).then_some(())?;
    info.nested(CONTEXT_0)?.expect(OCTET_STRING)
}

/// `SafeBag ::= SEQUENCE { bagId, [0] bagValue, bagAttributes SET OPTIONAL }`.
fn safe_bag(mut bag: Der<'_>) -> Option<Entry<'_>> {
    let kind = der::oid(bag.expect(OID)?)?;
    let mut value = bag.nested(CONTEXT_0)?;
    let (alias, keyed) = bag.expect(SET).map(attributes).unwrap_or_default();
    match kind.as_str() {
        CERT_BAG => {
            let mut cert = value.nested(SEQUENCE)?;
            let cert_type = der::oid(cert.expect(OID)?)?;
            (cert_type == X509_CERTIFICATE).then_some(())?;
            let der = cert.nested(CONTEXT_0)?.expect(OCTET_STRING)?;
            // A key's certificate shares its `localKeyId`.
            Some(Entry::Certificate {
                alias,
                der,
                trusted: !keyed,
            })
        }
        KEY_BAG => {
            let key = x509::private_key_info(value.nested(SEQUENCE)?)?;
            Some(Entry::PrivateKey { alias, key })
        }
        _ => None,
    }
}

/// The `friendlyName` attribute (a BMP, UTF-16BE, string) and whether a
/// `localKeyId` pairs the bag with a key.
fn attributes(attributes: &[u8]) -> (Option<String>, bool) {
    let mut name = None;
    let mut keyed = false;
    let mut attributes = Der::new(attributes);
    while let Some(mut attribute) = attributes.nested(SEQUENCE) {
        let Some(oid) = attribute.expect(OID).and_then(der::oid) else {
            continue;
        };
        match oid.as_str() {
            LOCAL_KEY_ID => keyed = true,
            FRIENDLY_NAME => {
                let Some(bmp) = attribute.nested(SET).and_then(|mut s| s.next()) else {
                    continue;
                };
                let units: Vec<u16> = bmp
                    .content
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&pair| u16::from_be_bytes(pair))
                    .collect();
                name = Some(String::from_utf16_lossy(&units));
            }
            _ => {}
        }
    }
    (name, keyed)
}
