# Infrastructure configuration

**Status: planned, not implemented.**

## The problem

A system's cryptography is not only in its source. Which key exchange a server
offers, which key type a certificate is issued with and which algorithm a VPN
uses are often chosen in configuration files and infrastructure code that
Shorwatch does not read today. A scan of the application can come back clean
while the host in front of it still negotiates RSA or ECDH.

## What it would read

| Kind | Examples |
|---|---|
| Directive files | `sshd_config` (`KexAlgorithms`, `HostKeyAlgorithms`), nginx and Apache TLS directives (`ssl_ciphers`, `ssl_ecdh_curve`), `openssl.cnf`, WireGuard and strongSwan configuration, DNS server zone and key settings |
| Infrastructure as code | Terraform key specifications for the major clouds (an RSA or ECC key spec on a managed key) |
| Kubernetes manifests | Certificate resources that name a private key algorithm |

## How it would fit

Mostly new frontends and rules, with little engine work.

- **Kubernetes manifests** need rules only: the YAML frontend already flattens
  them into properties.
- **Directive files** (`name value` or `name = value` per line) need one
  generic line-based frontend, chosen by file name like the build files. They
  get their own platform, so a rule written for them never fires on Spring or
  .NET configuration, and the cross-file link ignores them.
- **Terraform** needs a parser for its language and one rule folder per cloud.
- Rules stay YAML, with profiles and documentation pages like the rest.

## Hardware and secure boot

Smartcards, hardware security modules and TPMs are mostly invisible to a static
scan. What is visible, such as a PKCS#11 provider configuration or keys in a
firmware database, would be reported as **inventory** (hardware to migrate),
never as findings.

## Left out

- Container image and package signatures: they are not in the repository.
- Live scanning of running servers. Shorwatch reads files.

## Undecided

- The order of the formats. The Kubernetes rules are the cheapest and the
  directive frontend covers the most files.
- How to model a protocol setting that is a list of preferences, where one weak
  entry is a risk only if it is negotiated.
