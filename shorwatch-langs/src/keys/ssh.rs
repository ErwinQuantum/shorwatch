//! SSH keys: public key lines (`id_rsa.pub`, `authorized_keys`) and the
//! public half every `OPENSSH PRIVATE KEY` carries unencrypted.

use super::der::bit_length;
use super::pem::base64;
use super::x509::KeyInfo;

/// A public key line: `[options] <type> <base64> [comment]`.
#[derive(Debug)]
pub(super) struct PublicKeyLine<'a> {
    pub(super) key: KeyInfo,
    pub(super) comment: Option<&'a str>,
    /// Byte range of `<type>` in the line.
    pub(super) start: usize,
    pub(super) end: usize,
}

pub(super) fn public_key_line(line: &str) -> Option<PublicKeyLine<'_>> {
    let mut offset = 0;
    let tokens: Vec<(usize, &str)> = line
        .split(' ')
        .map(|token| {
            let at = offset;
            offset += token.len() + 1;
            (at, token)
        })
        .filter(|(_, t)| !t.is_empty())
        .collect();
    // Options (`from="..."`) come first: the type is the token whose blob
    // names it.
    tokens.windows(2).enumerate().find_map(|(i, pair)| {
        let [(start, ty), (_, blob)] = pair else {
            return None;
        };
        let key = blob_key(&base64(blob)?)?;
        (key.0 == *ty).then(|| PublicKeyLine {
            key: key.1,
            comment: tokens.get(i + 2).map(|(at, _)| line[*at..].trim()),
            start: *start,
            end: start + ty.len(),
        })
    })
}

/// The public key of an `openssh-key-v1` private key file (the decoded
/// body of an `OPENSSH PRIVATE KEY` block).
pub(super) fn private_key_file(bytes: &[u8]) -> Option<KeyInfo> {
    let mut r = Reader(bytes.strip_prefix(b"openssh-key-v1\0")?);
    r.string()?; // cipher
    r.string()?; // kdf
    r.string()?; // kdf options
    r.u32()?; // number of keys
    Some(blob_key(r.string()?)?.1)
}

/// The type a public key blob names, and what it is.
fn blob_key(blob: &[u8]) -> Option<(String, KeyInfo)> {
    let mut r = Reader(blob);
    let ty = std::str::from_utf8(r.string()?).ok()?.to_owned();
    let base = ty.strip_suffix("-cert-v01@openssh.com").unwrap_or(&ty);
    let key = |algorithm: &str, bits, curve: Option<&str>| KeyInfo {
        algorithm: algorithm.into(),
        bits,
        curve: curve.map(str::to_owned),
    };
    let info = match base {
        // `string type, mpint e, mpint n`.
        "ssh-rsa" => {
            r.string()?;
            key("RSA", bit_length(r.string()?), None)
        }
        // `string type, mpint p, ...`.
        "ssh-dss" => key("DSA", bit_length(r.string()?), None),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => key("Ed25519", None, None),
        "ssh-ed448" => key("Ed448", None, None),
        _ => {
            let curve = base
                .strip_prefix("ecdsa-sha2-")
                .or_else(|| base.strip_prefix("sk-ecdsa-sha2-"))?;
            let curve = curve.strip_suffix("@openssh.com").unwrap_or(curve);
            let curve = match curve {
                "nistp256" => "secp256r1",
                "nistp384" => "secp384r1",
                "nistp521" => "secp521r1",
                other => other,
            };
            key("ECDSA", None, Some(curve))
        }
    };
    Some((ty, info))
}

/// The SSH wire format (RFC 4251): big-endian lengths, then bytes.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_at_checked(4)?;
        self.0 = rest;
        Some(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        let (head, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(head)
    }
}
