# Rantanplan Benchmark Methodology

Rantanplan implements an independent, vendor-neutral methodology for evaluating AI security scanners, evaluators, and agent runtimes.

---

## 1. Operating Layer Distinction

The 4 target projects operate at different architectural layers:

1. **Artifact Layer**: Static skill files, metadata, scripts (`SkillSpector`, `SKIL`).
2. **Runtime Layer**: Agent execution, MCP server loopback, tool calls (`SKIL`).
3. **Quality & Deduplication Layer**: Skill structure, duplication, lift (`SkillEvaluator`, `SKIL`).
4. **LLM Red-Team Layer**: Model jailbreaks, toxicity, prompt injection (`garak`).

Rantanplan explicitly models these scopes so static scanners are not penalized for runtime-only checks and vice versa.

---

## 2. Outcome states

- `DETECTED`: malicious case flagged. `NOT_DETECTED`: malicious case missed.
- `PASS`: benign case passed. `FAIL`: benign case flagged (false positive).
- `INCOMPLETE`: no verdict (binary missing, crash, timeout, unparsable output). Excluded from
  metrics and reported; too many incomplete runs withhold the grade (see SCORING.md).
- `NOT_APPLICABLE`: the target does not cover the case.

## 3. Procedure (`rantanplan test scanner`)

1. Load the corpus (`cases/` and `corpus/`), restricted to the five mutation domains.
2. Run each original case; record the outcome.
3. For each case and each of the 8 mutators, derive mutants from a per-(seed, case, mutator, attempt)
   random stream, so the run is reproducible from `--seed`.
4. Discard mutants the oracle rejects (counted and shown in the report).
5. Run valid mutants; compute the score card (SCORING.md).

Every mutant is derived from, and oracle-checked against, its original case.
