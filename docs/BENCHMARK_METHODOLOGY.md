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

## 2. Applicability Matrix States

- `DETECTED`: Vulnerability correctly flagged on malicious test case.
- `NOT_DETECTED`: Scanner missed vulnerability on malicious test case.
- `PASS`: Scanner correctly passed benign control test case.
- `FAIL`: False positive flagged on benign control test case.
- `ERROR`: Process execution crashed or returned unexpected exit code (NEVER counted as NOT_DETECTED).
- `TIMEOUT`: Execution exceeded wall-clock timeout limit.
- `NOT_APPLICABLE`: Case falls outside scanner's operating scope (NEVER counted as a miss).
- `SKIPPED_REQUIREMENT`: Missing optional hardware/software requirement (e.g. Docker, GPU).
