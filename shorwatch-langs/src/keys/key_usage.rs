//! The `keyUsage` extension of a certificate (RFC 5280 section 4.2.1.3): what
//! the subject's public key is for, in the CA's own words.

use shorwatch_core::Usage;

use super::der::{self, BIT_STRING, Der, OCTET_STRING, OID, SEQUENCE};

/// `id-ce-keyUsage`, `{ id-ce 15 }`.
const KEY_USAGE: &str = "2.5.29.15";
/// `[3] EXPLICIT Extensions`, and the two optional unique identifiers before it
/// (`[1]` and `[2]`, implicit bit strings).
const EXTENSIONS: u8 = 0xA3;
const ISSUER_UNIQUE_ID: u8 = 0x81;
const SUBJECT_UNIQUE_ID: u8 = 0x82;
const BOOLEAN: u8 = 0x01;
/// Extensions a certificate holds before the walk gives up: a hostile file
/// must not make it spin (real certificates have a dozen).
const MAX_EXTENSIONS: usize = 64;

/// The usage a certificate states, read from what follows the public key in
/// its `TBSCertificate`; `None` when there is no `keyUsage` or it says more
/// than one thing.
pub(super) fn of_certificate(tbs: &mut Der<'_>) -> Option<Usage> {
    tbs.skip_optional(ISSUER_UNIQUE_ID);
    tbs.skip_optional(SUBJECT_UNIQUE_ID);
    let mut extensions = tbs.nested(EXTENSIONS)?.nested(SEQUENCE)?;
    for _ in 0..MAX_EXTENSIONS {
        let mut extension = extensions.nested(SEQUENCE)?;
        let id = der::oid(extension.expect(OID)?)?;
        let mut value = extension.next()?;
        if value.tag == BOOLEAN {
            value = extension.next()?; // `critical`
        }
        if id == KEY_USAGE && value.tag == OCTET_STRING {
            let bits = Der::new(value.content).expect(BIT_STRING)?;
            return usage(bits);
        }
    }
    None
}

/// The usage of a `KeyUsage` bit string (its first byte counts the unused
/// bits, and bit 0 is the most significant one after it).
///
/// The bits fall in three families with a different successor each: signing
/// (`digitalSignature`, `nonRepudiation`, and the certificate and CRL signing
/// of a CA), key transport (`keyEncipherment`, and `dataEncipherment`, the
/// direct enciphering of data), and key agreement. A certificate that asserts
/// more than one family (an RSA TLS certificate that signs the handshake and
/// also wraps the pre-master secret is the common case) has no single usage,
/// and the profile does not restrict the combinations.
fn usage(bits: &[u8]) -> Option<Usage> {
    let bit = |n: usize| {
        bits.get(1 + n / 8)
            .is_some_and(|byte| byte & (0x80 >> (n % 8)) != 0)
    };
    let signature = bit(0) || bit(1) || bit(5) || bit(6);
    let transport = bit(2) || bit(3);
    // `encipherOnly` and `decipherOnly` (7, 8) mean nothing without it.
    let agreement = bit(4);
    match (signature, transport, agreement) {
        (true, false, false) => Some(Usage::Signature),
        (false, true, false) => Some(Usage::KeyTransport),
        (false, false, true) => Some(Usage::KeyAgreement),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[unused bits, byte 0, byte 1]`: `digitalSignature` is 0x80 of the
    /// first byte, `decipherOnly` the top bit of the second.
    #[test]
    fn each_family_is_one_usage() {
        assert_eq!(usage(&[7, 0x80]), Some(Usage::Signature)); // digitalSignature
        assert_eq!(usage(&[6, 0x40]), Some(Usage::Signature)); // nonRepudiation
        assert_eq!(usage(&[1, 0x06]), Some(Usage::Signature)); // keyCertSign, cRLSign
        assert_eq!(usage(&[5, 0x20]), Some(Usage::KeyTransport)); // keyEncipherment
        assert_eq!(usage(&[4, 0x10]), Some(Usage::KeyTransport)); // dataEncipherment
        assert_eq!(usage(&[3, 0x08]), Some(Usage::KeyAgreement)); // keyAgreement
    }

    #[test]
    fn a_certificate_that_does_several_things_has_no_single_usage() {
        assert_eq!(usage(&[5, 0xA0]), None); // digitalSignature + keyEncipherment
        assert_eq!(usage(&[3, 0x88]), None); // digitalSignature + keyAgreement
        assert_eq!(usage(&[0, 0x00]), None); // nothing asserted
    }

    #[test]
    fn the_second_byte_only_counts_with_key_agreement() {
        // encipherOnly (7) with keyAgreement (4): key agreement.
        assert_eq!(usage(&[7, 0x09, 0x00]), Some(Usage::KeyAgreement));
        // decipherOnly (8) alone says nothing.
        assert_eq!(usage(&[7, 0x00, 0x80]), None);
        // A truncated string reads as no bits, never panics.
        assert_eq!(usage(&[]), None);
    }
}
