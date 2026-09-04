# ADR 0002: Metamorphic Testing & Invariant Preservation

## Status
Accepted

## Context
Standard security benchmarks rely on static pass/fail test cases. However, adversarial evasions work by introducing semantic or structural mutations where the security invariant remains unchanged, but the scanner fails to detect it (`scanner(original) = vulnerable`, `scanner(mutated) = safe`).

## Decision
Rantanplan uses **Metamorphic Testing** as a foundational architectural principle. Every mutation is subjected to an explicit Semantic Invariant Oracle check (`internal/oracle/validator.go`) before being passed to a scanner target. Mutations that accidentally destroy the vulnerability (e.g. introducing defensive negations) are rejected to prevent invalid bypass false positives.

## Consequences
- Ensures discovered evasions represent genuine scanner blind spots rather than invalid test cases.

