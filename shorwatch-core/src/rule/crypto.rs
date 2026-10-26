//! What kind of cryptography an algorithm is: its primitive, what it is used
//! for and how strong it is, classically and against a quantum attacker.
//! Reports turn this into inventories such as a CycloneDX CBOM.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoProperties {
    pub primitive: Primitive,
    /// What the detected uses do with the algorithm.
    #[serde(default)]
    pub functions: Vec<CryptoFunction>,
    /// The parameter set the rule implies, e.g. `128` for AES-128.
    #[serde(default)]
    pub parameter_set: Option<String>,
    /// Classical security in bits, when the rule pins it down.
    #[serde(default)]
    pub classical_security_level: Option<u32>,
    /// NIST post-quantum security category (0 = broken by a quantum
    /// computer; 1 = at least as hard as AES-128 key search; up to 5).
    pub nist_quantum_security_level: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Primitive {
    /// Public-key encryption (RSA, ElGamal).
    Pke,
    Signature,
    /// Key agreement (DH, ECDH).
    KeyAgree,
    /// Key encapsulation (ML-KEM).
    Kem,
    BlockCipher,
    /// Authenticated encryption (AES-GCM).
    Ae,
    Hash,
    Mac,
    /// Key material that may serve several primitives (generic EC keys).
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoFunction {
    Keygen,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Keyderive,
    Encapsulate,
    Decapsulate,
    Digest,
    Tag,
}
