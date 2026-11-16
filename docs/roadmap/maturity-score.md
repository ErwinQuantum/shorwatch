# Post-quantum maturity score

**Status: planned, not implemented.**

## The problem

A report lists findings. It does not answer the question a team gets asked:
*how far along are we?* A project with 40 vulnerable uses and 30 already
hybrid is in a different place from one with 40 and none, and the list does
not show it.

## What it would do

Per project, three numbers: how much of the cryptography found is **migrated**
(post-quantum), **in transition** (hybrid, classical beside post-quantum) and
**vulnerable**. A single percentage is possible, but the three counts come
first.

Two related measures:

- **Crypto agility:** whether an algorithm is hard-coded at the use site or
  comes from configuration. A project that reads `jwt.algorithm` from a file
  can migrate by changing the file; one that writes `"RS256"` in code cannot.
- **Deadlines:** the NIST IR 8547 dates (quantum-vulnerable public-key
  cryptography deprecated after 2030 and disallowed after 2035) shown against
  the findings of each project.

## How it would fit

- Most of what it needs exists. A finding already has a status (vulnerable, in
  transition) and, when its value was resolved through a constant or a
  property, says so; that is the agility signal.
- What is missing: counting post-quantum uses as *migrated* (today a safe
  algorithm produces no finding), and exposing the "resolved indirectly" flag
  on the finding.
- Reports gain a summary block. The CBOM would be the natural place for the
  safe cryptography, which is the other half of the denominator.

## Left out

- A score that hides the findings. It summarises them, and every number links
  to the list behind it.
- Grading projects against each other.

## Undecided

- What counts in the denominator: every cryptographic call, or only those a
  rule recognises.
- How to weigh a test file against production code.
