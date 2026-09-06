# Rantanplan Scanner Scope & Operational Layer Specification

Rantanplan models the 4 primary target scanner projects explicitly by operational layer to ensure fair, vendor-neutral evaluation.

---

## 1. Operating Layer Mapping

```text
               RANTANPLAN TESTBENCH FRAMEWORK
  ┌───────────────────┬───────────────────┬───────────────────┐
  │                   │                   │                   │
  ▼                   ▼                   ▼                   ▼
Artifact Layer     Runtime Layer      Quality Layer     Security & Governance
  │                   │                   │                   │
SkillSpector        garak           SkillEvaluator          SKIL
(AST / Patterns)  (Red-Team LLM)    (Tier 1/2/3 Eval)   (Lint/Scan/Verify/Attest)
```

---

## 2. Target Project Profiles

### SkillSpector (NVIDIA)
- **Primary Layer**: Static Skill Artifact Inspection.
- **Capabilities**: AST parsing, static pattern detection, YARA integration, OSV dependency analysis, MCP tool poisoning detection.
- **Input**: `SKILL.md`, scripts, configuration manifests.

### garak (NVIDIA)
- **Primary Layer**: LLM Red-Team & Behavioral Vulnerability Scanning.
- **Capabilities**: Prompt injection probes, jailbreaks (DAN), data leakage detectors, toxicity evaluation, hallucination testing.
- **Input**: Interactive LLM endpoints, local mock REST targets.

### SkillEvaluator (NVIDIA)
- **Primary Layer**: Skill Quality, Redundancy & Task Performance Benchmarking.
- **Capabilities**: Tier 1 linting/PII, Tier 2 deduplication (semantic duplicate, subset, superset, related), Tier 3 agent evaluation datasets.
- **Input**: Skill directories, candidate skill catalogs.

### SKIL (Security & Governance)
- **Primary Layer**: Full-lifecycle Skill Security, Provenance & Runtime Governance.
- **Capabilities**: `validate`, `lint`, `scan` (static + semantic), `verify`, `eval`, `sbom`, `attest`, `package`, `policy`, `trust` graph, `proxy` enforcement.
- **Input**: Skill artifacts, packages (`.tgz`), signed attestations, policy configurations.

