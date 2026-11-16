# Roadmap

What Shorwatch does today is in the [README](../../README.md). These pages
describe what it does **not** do yet, and how each piece would be built.

**Nothing here is implemented.** Each page opens with its status, none gives a
date, and the order below is not a promise. The pages exist so that a gap is
understood, not hidden: what a scan skips today is also printed in every
report as *not analyzed*, so a report never reads as clean for code Shorwatch
did not read.

Every page follows the same outline: the problem, what the tool would do, where
it fits in the architecture, what stays out, and what is still undecided.

## Pages

| Page | In one line |
|---|---|
| [Quantum resource estimator](quantum-resource-estimator.md) | How big a quantum computer each key found would need, from published estimates |
| [Migration advisor](migration-advisor.md) | An optional, labelled estimate of the effort to migrate a finding |
| [Post-quantum maturity score](maturity-score.md) | Migrated, hybrid and vulnerable per project, and how hard-coded each algorithm is |
| [Infrastructure configuration](infrastructure-config.md) | sshd, nginx, OpenSSL, WireGuard, strongSwan, Terraform and certificate manifests |
| [Razor views and `web.config`](razor-and-web-config.md) | The rest of an ASP.NET project |
| [More languages](more-languages.md) | Python, Go, TypeScript, F# and Visual Basic |
| [Signed artifacts](signed-artifacts.md) | Signatures inside JAR and APK files |

## Also planned, without a page yet

- Editor integration through LSP: findings underlined as you type
- Pull-request mode: report only what a change introduces
- A GitHub Action on the Marketplace, and `shorwatch fix` to apply the
  suggested fixes
- More configuration formats (Micronaut, Quarkus TLS) and message brokers
- C#: more JWT libraries

## Principles that every item has to keep

- **Detection is deterministic.** The same input gives the same findings.
  Anything probabilistic, such as a language model, only *annotates* a finding
  and says so.
- **Rules are data.** A new detection should be a YAML file, not a change to
  the engine. Most pages below are new frontends plus rules for that reason.
- **Scanned repositories are untrusted.** Every new reader is bounded and
  never prints control characters or key bodies.
- **Estimates are labelled as estimates**, with their source.
