# Known Limitations

Read this before relying on a Rantanplan grade.

1. **Only one real scanner has been scored, once.** SKIL v0.6.0 was built from source and scored
   ([benchmarks/skil-v0.6.0.md](benchmarks/skil-v0.6.0.md)); the SKIL adapter is verified against its real
   JSON output (recorded in `tests/fixtures/`). The adapters for SkillSpector, garak, Cisco, Snyk,
   Tencent, promptfoo and SkillEvaluator are only tested against fake binaries that follow the output
   format they *assume*; treat their scores as unverified until each has been run for real. A single
   run on a template corpus is a data point, not a verdict, and some "misses" are scope differences
   (e.g. skil may not treat destructive commands written as prose as in scope).
2. **The oracle is a reference implementation, not ground truth about the world.** Meaning is
   defined by `semantics.py` (English lexicon, sentence-level negation, shallow code patterns).
   A mutation is "valid" if this reference says the meaning is unchanged. Weaknesses of the reference
   (e.g. a benign sentence mixing a secret and a transfer verb is read as exfiltration) can mislabel
   mutants. Corpus labels are independently written and checked against it
   (`rantanplan verify-ground-truth`), which catches inconsistencies but not shared blind spots.
3. **Scope.** Mutation scoring covers five domains: `secret.exfiltration`, `prompt.injection`,
   `code.execution`, `artifact.obfuscation`, `mcp.tool-poisoning`. Cases in other domains
   (licences, dependencies, runtime policy, LLM red-teaming) are loaded but not mutation-scored.
4. **Corpus size.** About 100 generated cases plus 6 hand-written ones. Wilson intervals are
   reported so small-sample metrics are visible; several structural/cross-file metrics rest on
   `n` of 8-30.
5. **Templated attacks.** The corpus is template-generated, clean-room and English. It measures
   robustness to *surface changes of known attack shapes*, not discovery of unknown attack classes.
6. **Circular ceiling.** `mock-strict` shares the oracle's semantics and always scores A+.
7. **Mock-profile code in real adapters.** Several adapters still contain a `TargetProfile.MOCK`
   shortcut used by `demo`; it must not be used to score a real scanner (`test scanner` always uses
   the offline profile).
8. **Platform.** Sandboxing relies on POSIX process groups; Windows is untested.
