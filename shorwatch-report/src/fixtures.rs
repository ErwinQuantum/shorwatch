//! A small, realistic scan shared by the renderer tests: findings in Java and
//! YAML, one in transition, one with a fix, one in test code whose value
//! comes through a parameter.

use shorwatch_core::ir::{FlowStep, Location, Position};
use shorwatch_core::rule::{
    Category, CryptoFunction, CryptoProperties, Primitive, Reference, Severity,
};
use shorwatch_core::{CodeRole, Finding, HybridEvidence, Status, SuggestedFix};

use crate::Scan;

const CONFIG: &str = "\
package com.acme.auth;

public class AuthConfig {
    KeyPair keys() throws Exception {
        var generator = KeyPairGenerator.getInstance(\"RSA\");
        return generator.generateKeyPair();
    }

    SecretKey dataKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(\"AES\");
\tgenerator.init(128);
        return generator.generateKey();
    }
}
";

const SIGNER: &str = "\
class Signer {
    Signature[] signers() throws Exception {
        return new Signature[] { Signature.getInstance(\"SHA256withECDSA\"), Signature.getInstance(\"ML-DSA-65\") };
    }
}
";

const SIGNER_TEST: &str = "\
class SignerTest {
    KeyPair fixture(String algorithm) throws Exception {
        return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
    }

    KeyPair rsa() throws Exception {
        return fixture(\"RSA\");
    }
}
";

const YAML: &str = "\
spring:
  security:
    oauth2.resourceserver.jwt:
      jws-algorithms: [RS256]
";

fn location(line: u32, start: u32, end: u32) -> Location {
    Location {
        start: Position {
            line,
            column: start,
        },
        end: Position { line, column: end },
        start_byte: 0,
        end_byte: 0,
    }
}

fn reference(title: &str, url: &str) -> Reference {
    Reference {
        title: title.into(),
        url: url.into(),
    }
}

fn shor(rule_id: &str, algorithm: &str, path: &str, at: Location) -> Finding {
    Finding {
        rule_id: rule_id.into(),
        algorithm: algorithm.into(),
        category: Category::Shor,
        severity: Severity::High,
        status: Status::Vulnerable,
        title: format!("{algorithm} is broken by Shor's algorithm"),
        message: format!("{algorithm} usage detected."),
        suggestion: "Plan a protocol migration to ML-KEM (FIPS 203) for key establishment and \
                     ML-DSA (FIPS 204) for signatures; hybrid schemes keep classical security \
                     during the transition."
            .into(),
        references: vec![
            reference(
                "FIPS 203: ML-KEM",
                "https://csrc.nist.gov/pubs/fips/203/final",
            ),
            reference(
                "FIPS 204: ML-DSA",
                "https://csrc.nist.gov/pubs/fips/204/final",
            ),
        ],
        path: path.into(),
        role: CodeRole::Production,
        location: at,
        detail: None,
        flow: Vec::new(),
        hybrid_evidence: None,
        fix: None,
        crypto: Some(crypto(Primitive::Pke, None, 0)),
    }
}

fn crypto(primitive: Primitive, parameter_set: Option<&str>, level: u8) -> CryptoProperties {
    CryptoProperties {
        primitive,
        functions: vec![CryptoFunction::Keygen, CryptoFunction::Encrypt],
        parameter_set: parameter_set.map(str::to_owned),
        classical_security_level: parameter_set.and_then(|p| p.parse().ok()),
        nist_quantum_security_level: level,
    }
}

pub(crate) fn scan() -> Scan {
    let config = "src/main/java/com/acme/auth/AuthConfig.java";
    let signer = "src/main/java/com/acme/auth/Signer.java";
    let yaml = "src/main/resources/application.yml";
    let signer_test = "src/test/java/com/acme/auth/SignerTest.java";

    let rsa = shor("jvm.jca.rsa", "RSA", config, location(5, 25, 60));
    let aes = Finding {
        rule_id: "jvm.jca.aes-128".into(),
        algorithm: "AES-128".into(),
        category: Category::Grover,
        severity: Severity::Low,
        title: "AES-128 keeps only about 64 bits of security against Grover's algorithm".into(),
        message: "A 128-bit AES key detected.".into(),
        suggestion: "Use 256-bit keys (AES-256).".into(),
        references: vec![reference(
            "FIPS 197: AES",
            "https://csrc.nist.gov/pubs/fips/197/final",
        )],
        crypto: Some(crypto(Primitive::BlockCipher, Some("128"), 1)),
        fix: Some(SuggestedFix {
            description: "Use a 256-bit AES key".into(),
            location: location(11, 17, 20),
            replacement: "256".into(),
        }),
        ..shor("jvm.jca.aes-128", "AES-128", config, location(11, 2, 21))
    };
    let ecdsa = Finding {
        status: Status::InTransition,
        hybrid_evidence: Some(HybridEvidence {
            text: "ML-DSA-65".into(),
            location: location(3, 84, 95),
        }),
        ..shor("jvm.jca.ecdsa", "ECDSA", signer, location(3, 34, 75))
    };
    let jose = shor(
        "config.spring-boot.jose-rsa",
        "RSA (JOSE/JWT)",
        yaml,
        location(4, 24, 29),
    );
    let test = Finding {
        role: CodeRole::Test,
        flow: vec![
            FlowStep {
                path: None,
                location: location(7, 24, 29),
                note: "\"RSA\" is written here".into(),
            },
            FlowStep {
                path: None,
                location: location(7, 24, 29),
                note: "passed as algorithm to fixture(...)".into(),
            },
        ],
        ..shor("jvm.jca.rsa", "RSA", signer_test, location(3, 16, 55))
    };

    Scan {
        tool_version: "0.1.0".into(),
        findings: vec![rsa, aes, ecdsa, jose, test],
        sources: [
            (config, CONFIG),
            (signer, SIGNER),
            (yaml, YAML),
            (signer_test, SIGNER_TEST),
        ]
        .into_iter()
        .map(|(p, s)| (p.to_owned(), s.to_owned()))
        .collect(),
        files_scanned: 12,
        links: crate::SourceLinks::default(),
        projects: Vec::new(),
    }
}
