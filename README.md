# Rantanplan

> **AI Security Control Assurance through Cognitive Chaos and Adversarial Mutation Testing.**

[![Go Version](https://img.shields.io/badge/go-1.26-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-100%25%20pass-brightgreen.svg)]()

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
- [Go 1.26+](https://golang.org/doc/install) installed on your system.

### Build Rantanplan

```bash
git clone https://github.com/rantanplan-ai/rantanplan.git
cd rantanplan
go build -o bin/rantanplan ./cmd/rantanplan
```

Verify installation:

```bash
./bin/rantanplan target list
```

---

## 🛠️ Command Reference

### 1. Test Scanner Assurance (`test scanner`)
Evaluate a target scanner against the benchmark corpus:

```bash
# Terminal Dashboard Output
./bin/rantanplan test scanner --target skil --corpus corpus/scanner

# Standalone Interactive HTML Report
./bin/rantanplan test scanner --target skil --corpus corpus/scanner --format html --output report.html

# Machine-Readable SARIF or JUnit XML for CI
./bin/rantanplan test scanner --target skil --format sarif --output rantanplan.sarif
```

### 2. Differential Target Benchmarking (`compare`)
Compare multiple scanners side-by-side on an identical corpus/mutation matrix:

```bash
./bin/rantanplan compare --targets skil,skillspector,mock-naive,mock-strict --corpus corpus/scanner
```

### 3. Adaptive False-Negative Hunting (`hunt false-negative`)
Iteratively mutate a vulnerable fixture until the target scanner fails to detect it:

```bash
./bin/rantanplan hunt false-negative --target skil
```

### 4. Adaptive False-Positive Hunting (`hunt false-positive`)
Test if the scanner incorrectly flags benign defensive security documentation:

```bash
./bin/rantanplan hunt false-positive --target skil
```

### 5. Delta Debugging Minimization (`minimize`)
Shrink a complex multi-line evasion fixture into a 4-line minimal reproducer:

```bash
./bin/rantanplan minimize --target skil --fixture corpus/scanner/data-exfiltration/exfil_01.yaml
```

### 6. Test Agent Evaluator Assurance (`test evaluator`)
Audit whether an evaluator incorrectly awards `PASS` for accidental successes or unauthorized side effects:

```bash
./bin/rantanplan test evaluator
```

### 7. Cognitive Chaos Engineering (`test agent`)
Test how AI agents handle prompt ambiguity, unsupported assumptions, and entity confusion:

```bash
./bin/rantanplan test agent
```

### 8. CI Regression Gate (`gate`)
Enforce score thresholds in CI pipelines:

```bash
./bin/rantanplan gate --results rantanplan-results.json
```

### 9. Export Portable Regression Bundle (`export regression`)
Export a discovered evasion finding into a standalone regression fixture:

```bash
./bin/rantanplan export regression RAN-SCAN-SEM-004 --output regression_bundles/
```

---

## 🎯 How to Test Against SKIL

Rantanplan provides first-class support for testing **SKIL** (`skil scan`, `skil validate`, `skil verify`, `skil eval`).

### Local Testing Workflow

1. Ensure `skil` CLI binary is installed and accessible in your `PATH`.
2. Run Rantanplan against `skil`:

```bash
# Run full Scanner Assurance test suite against SKIL
./bin/rantanplan test scanner \
  --target skil \
  --corpus corpus/scanner \
  --format dashboard

# Generate an HTML report for SKIL
./bin/rantanplan test scanner \
  --target skil \
  --format html \
  --output skil-assurance-report.html
```

3. Hunt for evasions against SKIL:

```bash
./bin/rantanplan hunt false-negative --target skil
```

### GitHub Actions CI Integration

Add Rantanplan to your SKIL repository workflow (`.github/workflows/rantanplan-ci.yml`):

```yaml
name: SKIL Security Assurance Gate

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  assurance:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout SKIL
        uses: actions/checkout@v4

      - name: Install Rantanplan & SKIL
        run: |
          go build -o bin/rantanplan ./cmd/rantanplan

      - name: Run Rantanplan Scanner Assurance
        run: |
          ./bin/rantanplan test scanner \
            --target skil \
            --corpus corpus/scanner \
            --format json \
            --output rantanplan-results.json

      - name: Evaluate CI Gate
        run: |
          ./bin/rantanplan gate --results rantanplan-results.json
```

---

## 📁 Repository Structure

```text
rantanplan/
├── cmd/rantanplan/              # CLI main entrypoint
├── internal/
│   ├── model/                   # GroundTruth, Fixture, Finding, AssuranceScore schemas
│   ├── target/                  # Target interface & execution sandbox
│   ├── adapter/                 # Adapters (SKIL, SkillSpector, garak, promptfoo, Mock)
│   ├── mutation/                # 8 Metamorphic Mutators & LLM provider engine
│   ├── oracle/                  # Semantic Invariant Validator
│   ├── search/                  # Adaptive Evasion Search Engine
│   ├── minimizer/               # Delta Debugging Minimizer (ddmin)
│   ├── cognitive/               # Cognitive Chaos Engine & Fault Taxonomy
│   ├── evaluator/               # Evaluator Assurance & SkillEvaluator Dedup Benchmark
│   ├── assurance/               # Transparent Scoring Engine
│   ├── compare/                 # Differential Matrix Compare Engine
│   └── report/                  # Terminal, HTML, JSON, SARIF, JUnit Report Formatters
├── corpus/                      # Seed Fixture Corpus (Data Exfiltration, Prompt Injection, Hard Negatives)
├── docs/                        # Architecture, Scoring, Threat Model, ADRs 0001–0006
└── examples/                    # GitHub Actions & GitLab CI workflow examples
```

---

## 🔒 Security & Threat Model

Rantanplan operates under a strict isolation model:
- **Fixtures as Data**: Untrusted test case code is never executed directly during standard scanning.
- **No Shell Execution**: Subprocesses are launched via explicit `argv` slices without shell wrapper wrappers (`sh -c`).
- **Resource Limits**: Context timeouts (30s default), bounded stdout/stderr byte capture, and sanitized environment variables (`PATH`, `TMPDIR`, `HOME` pointing to temp dirs).

For full security analysis, see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 📄 License

Rantanplan is released under the [MIT License](LICENSE).

