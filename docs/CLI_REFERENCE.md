# Rantanplan CLI Reference

`rantanplan` is a single binary CLI for executing scanner assurance, evaluator auditing, cognitive chaos testing, differential benchmarking, adaptive evasion hunting, delta debugging minimization, and CI regression gating.

---

## Commands Summary

```bash
# 1. Scanner Assurance Mode
rantanplan test scanner --target skil --corpus corpus/scanner --format dashboard

# 2. Differential Comparison Matrix
rantanplan compare --targets skil,skillspector,mock-naive --corpus corpus/scanner

# 3. Adaptive False-Negative Hunting
rantanplan hunt false-negative --target skil

# 4. Adaptive False-Positive Hunting (Defensive Hard Negatives)
rantanplan hunt false-positive --target skil

# 5. Delta Debugging Minimization (Minimal Reproducer)
rantanplan minimize --target skil --fixture corpus/scanner/data-exfiltration/exfil_01.yaml

# 6. Mutation Generation
rantanplan mutate --fixture corpus/scanner/data-exfiltration/exfil_01.yaml

# 7. Evaluator Assurance Mode (Accidental Success Detection)
rantanplan test evaluator

# 8. Cognitive Chaos Engineering (Agent Ambiguity Testing)
rantanplan test agent

# 9. CI Regression Gate
rantanplan gate --results rantanplan.json --policy .rantanplan/gate.yaml

# 10. Portable Regression Bundle Export
rantanplan export regression RAN-SCAN-SEM-004 --output regression_bundles/

# 11. Corpus & Target Management
rantanplan corpus list
rantanplan target list
```

---

## Global Options

- `--target`: Name of target adapter (`skil`, `skillspector`, `mock-naive`, `mock-strict`, or custom executable name).
- `--corpus`: Path to fixture corpus directory.
- `--seed`: Random seed for reproducible mutation generation (default: `42151`).
- `--format`: Output format (`dashboard`, `terminal`, `json`, `sarif`, `junit`).
- `--output`: File path to save report output.

