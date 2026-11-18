//! How a public-key algorithm is used where it was found.
//!
//! The advice depends on it: RSA that signs moves to a post-quantum
//! signature, RSA that encrypts or wraps a key moves to a KEM. A rule names
//! the usage of each pattern (a `Signature` call is a signature, a `Cipher`
//! is a key transport); the finding keeps it.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Usage {
    /// Signing or verifying: the successor is a post-quantum signature.
    Signature,
    /// Encrypting to a public key, data or a key alike (a `Cipher` cannot say
    /// which), or wrapping one: a KEM takes its place.
    KeyTransport,
    /// Both parties contribute to the shared secret (Diffie-Hellman).
    KeyAgreement,
    /// Generating a key pair: says nothing about what the key will be used
    /// for.
    KeyGeneration,
    /// The code or configuration does not say. A rule states it on purpose,
    /// never by leaving the usage out.
    Unknown,
}

impl Usage {
    /// The name reports print and the rule files use.
    pub fn label(self) -> &'static str {
        match self {
            Usage::Signature => "signature",
            Usage::KeyTransport => "key-transport",
            Usage::KeyAgreement => "key-agreement",
            Usage::KeyGeneration => "key-generation",
            Usage::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
