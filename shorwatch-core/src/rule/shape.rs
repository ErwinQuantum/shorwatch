//! The shape of a key agreement: which side uses a fresh key, which a
//! long-lived one.
//!
//! Key agreement comes in shapes that need different advice (NIST SP 800-56A
//! names them by how many ephemeral and static keys each party contributes).
//! A rule states the shape only where the code or the name says so: the `E`
//! of `ECDHE` in a TLS suite, the `ES` of the JOSE `ECDH-ES` names. Anything
//! else is `undetermined`; the shape is never guessed from the code around it.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgreementShape {
    /// Both parties make a fresh key pair for each exchange (the TLS
    /// handshake's `ECDHE` and `DHE` suites; SP 800-56A C(2e, 0s)). ML-KEM,
    /// usually in a hybrid.
    EphemeralEphemeral,
    /// One party makes a fresh key for each operation and the other has a
    /// long-lived one: JOSE `ECDH-ES`, ECIES (SP 800-56A C(1e, 1s), "One-Pass
    /// Diffie-Hellman"). It already has the shape of a KEM: the sender
    /// encapsulates to the recipient's key.
    EphemeralStatic,
    /// Both parties use only long-lived key pairs, to authenticate each other
    /// (SP 800-56A C(0e, 2s), "Static Unified Model"). No one-to-one
    /// replacement: the protocol has to change.
    StaticStatic,
    /// The code does not say.
    Undetermined,
}

impl AgreementShape {
    /// The name reports print and the rule files use.
    pub fn label(self) -> &'static str {
        match self {
            AgreementShape::EphemeralEphemeral => "ephemeral-ephemeral",
            AgreementShape::EphemeralStatic => "ephemeral-static",
            AgreementShape::StaticStatic => "static-static",
            AgreementShape::Undetermined => "undetermined",
        }
    }
}

impl fmt::Display for AgreementShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
