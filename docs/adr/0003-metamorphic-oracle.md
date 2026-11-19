# ADR 0003: Oracle-gated metamorphic mutants

## Status
Accepted

## Context
A mutation that changes the *meaning* of a test case makes a scanner's "miss" correct. Counting such
mutants would blame scanners for the mutator's mistakes. Early prototypes applied mutations blindly
(for example replacing every `a`/`e` with a Cyrillic look-alike, including inside host names).

## Decision
Every mutant is checked against its **root** case by `MetamorphicOracle` before it is run. It is valid
only if (1) the label is unchanged, (2) the set of capability signals is unchanged, and (3) literal
indicators (hosts, destructive commands) are identical. Rejected mutants are counted and surfaced,
never scored. Meaning is defined by a transparent reference analyzer (`semantics.py`) that
deobfuscates (zero-width, BIDI, homoglyphs, base64, string concatenation, aliases) and honours
defensive negation.

## Consequences
* The oracle rejects roughly 0.25% of generated mutants (e.g. homoglyphs inside a command).
* Scores depend on the reference semantics; its blind spots are documented in LIMITATIONS.md.
* Mutators may be aggressive; the oracle, not the mutator, is the authority.
