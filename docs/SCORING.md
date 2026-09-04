# Rantanplan Scoring Methodology

Rantanplan employs a transparent, reproducible, vendor-neutral methodology to evaluate AI security controls.

---

## 1. Scanner Assurance Score (0.0 – 100.0)

The Scanner Assurance Score measures a scanner's detection quality, precision, and robustness against semantic, structural, and obfuscation mutations.

### Formula

$$ \text{AssuranceScore} = 0.25 \times \text{Recall} + 0.25 \times \text{Precision} + 0.15 \times \text{SemanticRob} + 0.10 \times \text{StructRob} + 0.10 \times \text{CrossRob} + 0.10 \times \text{ObfRob} + 0.05 \times \text{NegSafety} $$

### Metric Dimensions

| Dimension | Description | Weight |
| :--- | :--- | :---: |
| **Recall** | Percentage of true vulnerable seed fixtures detected | 25% |
| **Precision** | Percentage of reported findings that correspond to true vulnerabilities | 25% |
| **Semantic Robustness** | Detection stability under semantic paraphrasing and lexical synonyms | 15% |
| **Structural Robustness** | Detection stability when instructions are split across sections/lines | 10% |
| **Cross-File Robustness** | Detection stability when capability chains span separate files | 10% |
| **Obfuscation Robustness** | Detection stability under code aliasing, indirection, and encoding | 10% |
| **Negative-Context Safety** | False-positive avoidance when suspicious terms appear in defensive context | 5% |

---

## 2. Letter Grade Grading Scale

| Grade | Overall Score Range | Description |
| :---: | :---: | :--- |
| **A+** | 97.0 – 100.0 | Outstanding adversarial robustness across all mutation dimensions |
| **A**  | 90.0 – 96.9  | Strong security assurance with minor blind spots under edge obfuscation |
| **B**  | 80.0 – 89.9  | Moderate robustness; vulnerable to cross-file or semantic paraphrasing |
| **C**  | 70.0 – 79.9  | Weak adversarial resistance; fails on basic keyword substitutions |
| **F**  | 0.0 – 69.9   | Unreliable control; high false-negative or false-positive rate |

---

## 3. Reproducibility Guarantee

Every score output must contain complete reproducibility metadata:
- Random Seed
- Target Binary Version & Hash Digest
- Rantanplan Corpus Version & Seed Digest
- Mutator Configuration & Depth Limits
- Operating System & Execution Environment

