# Migration advisor

**Status: planned, not implemented.**

## The problem

Detection tells you *where* a quantum-vulnerable algorithm is. Planning the
migration needs a second answer: how much work is it? Replacing one literal is
a line; replacing a signature scheme used by three services is a project. A
tool can narrow that down, but only roughly.

## What it would do

An optional step that reads the findings and, for each, estimates:

- the **scope** of the change: a line, a function, a class, or across modules;
- a rough **effort**;
- a short **rationale**, in plain words.

It is a language-model call with a fixed output format, and every result is
labelled as an estimate.

## How it would fit

- A separate crate. The core, the rules and the reports know nothing about it.
- Input: the JSON report plus the enclosing function or class of each finding
  and its callers in the same file. That needs the position of scopes in the
  intermediate representation, which today only knows their names.
- Output: a fixed JSON schema, rendered next to the finding in the reports.
- **Never edits code.** Fixes stay the deterministic ones the rules carry.

## Safeguards that are part of the design

- **Off by default**, and off in CI unless asked for.
- **A local model first.** A hosted one is opt-in, and the page about it says
  exactly what text is sent and where.
- **Reproducible as far as possible:** temperature zero, and results cached by
  a hash of the snippet.
- **Detection never depends on it.** A scan with the advisor off finds the same
  things.

## Left out

- Predicting which algorithm to migrate *to*: that is the rule's suggestion,
  based on the NIST standards.
- Any use of the model to decide whether something is a finding.

## Undecided

- The scale for effort (hours, t-shirt sizes, or only the scope).
- How to evaluate it: a set of real migrations to compare against.
