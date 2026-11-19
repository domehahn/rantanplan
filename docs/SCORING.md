# Rantanplan Scoring

Implemented in `src/rantanplan/scoring.py`. Every number is a proportion reported with its sample
size `n` and a Wilson 95% confidence interval.

## Metrics

| Metric | Definition |
| :--- | :--- |
| **Recall** | malicious original cases: `DETECTED / (DETECTED + NOT_DETECTED)` |
| **Specificity** | benign original cases: `PASS / (PASS + FAIL)` (`FAIL` = false positive) |
| **Semantic robustness** | share of `lexical` + `semantic` mutants still detected |
| **Structural robustness** | share of `split_instruction` + `code_alias` mutants still detected |
| **Cross-file robustness** | share of `cross_file` mutants still detected |
| **Obfuscation robustness** | share of `unicode` + `encoding` mutants still detected |
| **Negative-context safety** | defensive camouflage around an attack must still be detected, and defensive wording in benign text must not be flagged |

Robustness metrics are **conditional**: a mutant only counts if the scanner handled its parent
correctly. Mutation sensitivity is thereby measured separately from baseline recall/specificity.
Only mutants approved by the [metamorphic oracle](adr/0003-metamorphic-oracle.md) are counted.

## Overall score and grade

1. Weighted **geometric mean** of the metrics that have evidence (weights: recall 0.20, specificity
   0.20, semantic 0.10, structural 0.10, cross-file 0.10, obfuscation 0.15, negative-context 0.15).
   A zero in any metric yields 0, so a scanner that detects nothing cannot be averaged into a pass.
2. **Gating cap**: the overall score never exceeds `min(recall, specificity)`.
3. Grade: A+ >= 0.95, A >= 0.90, A- >= 0.85, B+ >= 0.80, B >= 0.75, B- >= 0.70, C+ >= 0.65,
   C >= 0.60, C- >= 0.55, D >= 0.50, otherwise F.

## When no grade is issued

* `INCOMPLETE` if more than 20% of runs produced no verdict (crash, timeout, unparsable output,
  binary missing), or if recall or specificity has no evidence at all.
  Runs without a verdict are never counted as detections or as passes.
* **Confidence `low`** if fewer than 30 scored runs exist or any metric has `n < 10`. `rantanplan gate`
  rejects low-confidence grades unless `--allow-low-confidence` is passed.

## Calibration

`rantanplan suite offline-core` scores four built-in targets and fails if the scale does not order
them sensibly: `mock-blind` (flags nothing) < `mock-naive` (keywords) <= `mock-strict`, and
`mock-paranoid` (flags every suspicious word) < `mock-strict`. See
[REFERENCE_BENCHMARK.md](REFERENCE_BENCHMARK.md). `mock-strict` uses the oracle's own reference
semantics, so it is a ceiling check, not evidence about any real scanner.
