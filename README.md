# Rantanplan

> **AI Security Control Assurance through Cognitive Chaos and Adversarial Mutation Testing.**

[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/rantanplan-ai/rantanplan/actions/workflows/ci.yml/badge.svg)](https://github.com/rantanplan-ai/rantanplan/actions/workflows/ci.yml)

**Rantanplan** is a vendor-neutral framework designed to test, benchmark, and stress-test the tools that claim to test AI systems.

Instead of asking *"Is this skill malicious?"*, Rantanplan asks:
- **Can the scanner be fooled by simple wording or structural changes?**
- **Can a semantically identical vulnerability evade detection?**
- **Does harmless security documentation trigger a false positive?**
- **Can an agent evaluator be fooled by accidental success or unauthorized side effects?**

---

## 💡 What is Rantanplan?

Rantanplan evaluates security scanners, evaluators, guardrails, policy engines, and agent runtimes through **Metamorphic Testing** and **Cognitive Chaos Injection**.

### Product Differentiation

| Tool | Focus | Question Answered |
| :--- | :--- | :--- |
| **SKIL** | Skill Governance & Trust | *Can this agent skill be trusted in production?* |
| **SkillSpector** | Static Skill Inspection | *Does this skill contain known rule violations?* |
| **garak** | LLM Vulnerability Scanning | *Can this model/agent be jailbroken?* |
| **SkillEvaluator** | Skill Benchmarking | *Does this skill improve task performance?* |
| **Rantanplan** | **Control Assurance** | ***Can the systems making those judgments be made to judge incorrectly?*** |

---

## ⚙️ How It Works

```text
Known Ground Truth (Independent Invariants)
       │
       ▼
Mutation Engine (8 Metamorphic Mutators)
       │
       ▼
Metamorphic Oracle (Verify Invariant Preservation)
       │
       ▼
Target Execution Sandbox (Subprocess Execution)
       │
       ▼
Normalized Findings & Scanner Assurance Score
```

1. **Independent Ground Truth**: Test cases define explicit ground-truth invariants (`secrets.read` + `network.external`) independent of external scanner outputs.
2. **Metamorphic Mutation**: Generates 8 classes of mutations:
   - **Lexical**: Synonym substitution (`secret` → `authentication material`, `send` → `transmit`).
   - **Semantic**: Paraphrasing direct attack prompts into maintenance/diagnostic terminology.
   - **Split-Instruction**: Breaking suspicious instructions across sections and lines.
   - **Cross-File**: Decomposing multi-step attack chains across `SKILL.md`, `references/reporting.md`, and `scripts/telemetry.py`.
   - **Code & Alias**: Variable aliasing, dynamic `getattr` dispatch, and environment wrappers.
   - **Unicode & Bidi**: Zero-width spaces (`U+200B`), Cyrillic homoglyphs (`а`), and BIDI overrides (`U+202E`).
   - **Encoding**: Base64 encoding and split string literal concatenation.
   - **Negative Context**: Hard negatives placing suspicious terms into defensive security guidelines ("Never send API keys").
3. **Metamorphic Oracle**: Verifies ground-truth preservation before running scanner targets to discard invalid mutation drift.
4. **Subprocess Isolation**: Runs external scanners in isolated temporary directory workspaces with process execution bounds (no shell wrapper execution, timeouts, environment variable whitelist).
5. **Assurance Scoring**: Calculates transparent metric breakdowns (Recall, Precision, Semantic Robustness, Structural Robustness, Cross-File, Obfuscation, Negative-Context Safety) and Letter Grades (`A+` to `F`).

---

## 🚀 Quick Start & Installation

### Prerequisites
- Python 3.12+ and [uv](https://docs.astral.sh/uv/) (or pip)
- Optional: the scanner binaries you want to test (`skil`, `skillspector`, `garak`, ...). Missing binaries are reported as `INCOMPLETE`, not as a pass.

### Install

```bash
git clone https://github.com/rantanplan-ai/rantanplan.git
cd rantanplan
uv sync --extra dev
uv run rantanplan --help
```

### Verify

```bash
uv run rantanplan doctor          # scanner binaries and versions
uv run rantanplan verify-ground-truth
uv run pytest
```

---

## 🛠️ Command Reference

| Command | Purpose |
| :--- | :--- |
| `doctor` | Check scanner installation, binary paths and version compatibility |
| `list [scanners\|cases\|capabilities]` | List registered scanners, test cases or canonical capabilities |
| `verify-ground-truth` | Validate all test cases against the ground-truth schema |
| `inventory` | Snapshot upstream capabilities of all scanners |
| `gaps` | Analyse capability coverage gaps across scanners |
| `hunt --target skil --mode false-negative\|false-positive` | Adaptive evasion / false-positive hunting via mutators |
| `minimize --target skil` | Delta-debug a test case down to a minimal reproducer |
| `suite [offline-core\|static\|garak\|runtime]` | Run a benchmark suite |
| `demo` | Zero-cost, network-independent demo matrix across all scanners |
| `benchmark` | Full benchmark and performance run |
| `gate --min-coverage N` | CI gate exit code based on verification criteria |
| `upstream check` | Upstream drift and compatibility monitoring |

See [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for details.

---

## 🎯 Testing Against SKIL

1. Install the `skil` binary and make sure it is on your `PATH` (or set `RANTANPLAN_SKIL_BIN`).
2. Run:

```bash
uv run rantanplan doctor
uv run rantanplan hunt --target skil --mode false-negative
uv run rantanplan hunt --target skil --mode false-positive
```

---

## 📁 Repository Structure

```text
rantanplan/
├── src/rantanplan/
│   ├── cli.py                   # Typer CLI entrypoint
│   ├── adapters/                # SKIL, SkillSpector, garak, promptfoo, Snyk, ...
│   ├── generators/              # Archive / bytecode / clean-room case generators
│   ├── targets/                 # Mock targets (MCP rug-pull, RAG canary, ...)
│   ├── reporting/               # HTML report
│   ├── execution.py             # Subprocess sandbox
│   ├── ground_truth.py          # Independent ground-truth loader
│   ├── metrics.py               # Scoring
│   ├── search.py                # Adaptive evasion search
│   └── upstream_drift.py        # Upstream drift monitor
├── corpus/scanner/              # Seed corpus (data exfiltration, hard negatives)
├── docs/                        # Architecture, scoring, threat model, ADRs
└── tests/
```

---

## 🔒 Security & Threat Model

- **Fixtures as data**: untrusted test case content is written to temp directories and passed to scanners, never executed directly.
- **No shell execution**: subprocesses are launched with explicit `argv` (`shell=False`).
- **Resource limits**: timeouts and sanitized environment.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 📄 License

MIT, see [LICENSE](LICENSE).
