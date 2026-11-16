# Quantum resource estimator

**Status: planned, not implemented.**

## The problem

A finding says *"RSA-2048 is broken by Shor's algorithm"*. It does not say how
far away that is, and "high severity" for a 1024-bit key and for a 4096-bit key
looks the same. People deciding what to migrate first want a sense of scale:
how large a quantum computer each key would need.

## What it would do

For each key or algorithm Shorwatch finds, print the resources a published
analysis says an attack needs: logical or physical qubits, and the running
time, for that key size or curve.

- Every number is **copied from a paper**, never computed by Shorwatch, and
  printed with its source and year, as an estimate under stated hardware
  assumptions.
- Examples of the kind of source it would use: Gidney's 2025 analysis, which
  puts RSA-2048 within reach of fewer than a million noisy qubits running for
  under a week ([arXiv:2505.15917](https://arxiv.org/abs/2505.15917)); and
  Litinski's 2023 analysis of 256-bit elliptic-curve keys, at (44 + 65/k)
  million Toffoli gates per key with k instances in parallel
  ([arXiv:2306.08585](https://arxiv.org/abs/2306.08585)).
- When there is no published estimate for a key size, it says so instead of
  interpolating.

Estimates keep falling, so the table has to be easy to update and to date.

## How it would fit

- A data file of estimates (algorithm, size or curve, source, year, assumptions),
  checked by a test that every row has a source. The same idea as the rule
  files: data, not code.
- Key size and curve are already facts for key material. For code, the size is
  often an argument (`initialize(2048)`), which the engine already reads.
- Reports gain a column. The CBOM could carry it as a property of the
  cryptographic asset.

## Left out

- No claim about *when* a machine of that size will exist. That is a forecast,
  not a measurement.
- No ranking of findings by it: severity stays what the rules say.

## Undecided

- Which hardware assumptions to show when sources disagree (error rates, cycle
  time).
- Whether to show one number per key or a range across sources.
