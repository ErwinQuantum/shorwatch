//! A minimal DER reader: tag, length, content. Enough to walk the
//! structures that name a key's algorithm; nothing is validated beyond
//! what reading them needs, and BER's indefinite lengths are not supported.

pub(super) const INTEGER: u8 = 0x02;
pub(super) const BIT_STRING: u8 = 0x03;
pub(super) const OCTET_STRING: u8 = 0x04;
pub(super) const OID: u8 = 0x06;
pub(super) const SEQUENCE: u8 = 0x30;
pub(super) const SET: u8 = 0x31;
pub(super) const UTC_TIME: u8 = 0x17;
pub(super) const GENERALIZED_TIME: u8 = 0x18;
/// `[0]`, constructed: explicit tags and optional fields.
pub(super) const CONTEXT_0: u8 = 0xA0;

/// A sequence of TLVs, read front to back.
#[derive(Debug, Clone, Copy)]
pub(super) struct Der<'a> {
    rest: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Tlv<'a> {
    pub(super) tag: u8,
    pub(super) content: &'a [u8],
}

impl<'a> Der<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The next TLV, or `None` at the end or on malformed input.
    pub(super) fn next(&mut self) -> Option<Tlv<'a>> {
        let (&tag, rest) = self.rest.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (length, rest) = match first {
            0..=0x7F => (usize::from(first), rest),
            0x81..=0x84 => {
                let n = usize::from(first & 0x7F);
                let (bytes, rest) = rest.split_at_checked(n)?;
                let length = bytes.iter().fold(0usize, |l, &b| (l << 8) | usize::from(b));
                (length, rest)
            }
            _ => return None,
        };
        let (content, rest) = rest.split_at_checked(length)?;
        self.rest = rest;
        Some(Tlv { tag, content })
    }

    /// The next TLV's content if it has `tag`.
    pub(super) fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let tlv = self.next()?;
        (tlv.tag == tag).then_some(tlv.content)
    }

    /// The next TLV's content as a nested reader, if it has `tag`.
    pub(super) fn nested(&mut self, tag: u8) -> Option<Der<'a>> {
        self.expect(tag).map(Der::new)
    }

    /// Skips the next TLV if it has `tag` (an optional field).
    pub(super) fn skip_optional(&mut self, tag: u8) {
        if self.rest.first() == Some(&tag) {
            self.next();
        }
    }
}

/// An OID in dotted form (`1.2.840.113549.1.1.1`).
pub(super) fn oid(content: &[u8]) -> Option<String> {
    let (&first, rest) = content.split_first()?;
    let mut arcs = vec![u64::from(first / 40).min(2), 0];
    arcs[1] = u64::from(first) - arcs[0] * 40;
    let mut value: u64 = 0;
    for &byte in rest {
        value = value.checked_mul(128)? | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    let dotted: Vec<String> = arcs.iter().map(u64::to_string).collect();
    Some(dotted.join("."))
}

/// The bit length of an unsigned big-endian integer (an RSA modulus).
pub(super) fn bit_length(integer: &[u8]) -> Option<u32> {
    let start = integer.iter().position(|&b| b != 0)?;
    let bytes = u32::try_from(integer.len() - start).ok()?;
    Some((bytes - 1) * 8 + (8 - integer[start].leading_zeros()))
}
