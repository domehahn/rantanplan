# Rantanplan Architecture Specification

Rantanplan is a vendor-neutral **Cognitive Chaos Engineering, Adversarial Mutation Testing, Differential Benchmarking, and Scanner Assurance Framework** for AI agents, agent skills, AI security scanners, evaluators, guardrails, and agent supervisors.

---

## High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Input ["Corpus & Ground Truth"]
        SeedCorpus["Seed Fixture Corpus"]
        GroundTruth["Independent Ground Truth Invariants"]
    end

    subgraph MutationEngine ["Extensible Mutation Engine"]
        Lexical["Lexical Mutator"]
        Semantic["Semantic Paraphraser"]
        Split["Split-Instruction Mutator"]
        CrossFile["Cross-File Decomposer"]
        CodeAlias["Code & Alias Mutator"]
        Unicode["Unicode & Bidi Mutator"]
        Encoding["Encoding & Obfuscation"]
        NegContext["Negative Context (Hard Negatives)"]
    end

    subgraph Oracle ["Metamorphic Oracle"]
        InvariantValidator["Semantic Invariant Validator"]
        PreservationCheck{"Ground Truth Preserved?"}
    end

    subgraph TargetSandbox ["Target Execution Sandbox"]
        SubprocessIsolator["Isolated Process Runner (No Shell)"]
        TempWorkspace["Isolated Temp Directory"]
        TargetAdapter["Target Adapter (SKIL / SkillSpector / Generic)"]
    end

    subgraph Assurance ["Analysis & Reporting"]
        Normalizer["Findings Normalizer"]
        ScoringEngine["Assurance Scoring Engine (Recall/Precision/Robustness)"]
        Minimizer["Delta Debugging Minimizer (ddmin)"]
        ReportGenerator["Reports (Terminal / JSON / Markdown / HTML)"]
    end

    SeedCorpus --> MutationEngine
    GroundTruth --> InvariantValidator
    MutationEngine --> InvariantValidator
    InvariantValidator --> PreservationCheck
    PreservationCheck -- Yes --> TempWorkspace
    PreservationCheck -- No --> RejectMutation["Discard Invalid Drift"]

    TempWorkspace --> TargetAdapter
    SubprocessIsolator --> TargetAdapter
    TargetAdapter --> Normalizer
    Normalizer --> ScoringEngine
    Normalizer --> Minimizer
    ScoringEngine --> ReportGenerator
```

---

## Core Domain Pipeline

1. **Seed Fixture & Ground Truth**: Every benchmark case defines explicit ground truth (`vulnerable: true/false`, capability sources/sinks, semantic invariants, expected scanner output). Ground truth is strictly independent of any target scanner under test.
2. **Metamorphic Mutation**: The Mutation Engine applies deterministic, seeded transformations across 8 categories (lexical, semantic paraphrasing, split instruction, cross-file, code alias, Unicode, encoding, and negative context).
3. **Oracle Verification**: Before running a scanner target on a mutated variant, the Metamorphic Oracle verifies that ground truth invariants remain intact (e.g. confirming that secret collection + external network sink still exists and defensive negations were not introduced accidentally).
4. **Isolated Target Execution**: Scanners are executed in isolated temp directories using strict process execution bounds (`subprocess` without shell wrappers, process-group timeout kill, sanitised environment variables).
5. **Normalization & Scoring**: Scanner outputs are normalized into per-run outcomes (`DETECTED`, `NOT_DETECTED`, `PASS`, `FAIL`, `INCOMPLETE`) and scored across 7 transparent metrics (see SCORING.md).

