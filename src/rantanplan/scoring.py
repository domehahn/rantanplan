"""
Transparent assurance scoring.

The overall score is a weighted geometric mean of the metrics, capped by the weaker of recall and
specificity, so no single strong metric can hide a failed one. Every number in a score card is a proportion with its sample size and a Wilson 95% interval, so a
reader can see how much evidence is behind a grade. Robustness metrics are *conditional*: a
mutant only counts if the scanner handled its parent correctly, so mutation sensitivity is
measured separately from baseline recall/specificity.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any

from rantanplan.models import AssuranceOutcome

SCORED = {
    AssuranceOutcome.DETECTED,
    AssuranceOutcome.NOT_DETECTED,
    AssuranceOutcome.PASS,
    AssuranceOutcome.FAIL,
}

WEIGHTS: dict[str, float] = {
    "recall": 0.20,
    "specificity": 0.20,
    "semantic_robustness": 0.10,
    "structural_robustness": 0.10,
    "cross_file_robustness": 0.10,
    "obfuscation_robustness": 0.15,
    "negative_context_safety": 0.15,
}

GRADES: tuple[tuple[float, str], ...] = (
    (0.95, "A+"), (0.90, "A"), (0.85, "A-"), (0.80, "B+"), (0.75, "B"), (0.70, "B-"),
    (0.65, "C+"), (0.60, "C"), (0.55, "C-"), (0.50, "D"),
)

MIN_SAMPLES_PER_METRIC = 10
MIN_TOTAL_SAMPLES = 30
MAX_INCOMPLETE_FRACTION = 0.20


@dataclass(frozen=True)
class RunRecord:
    """One scored execution (an original case or an oracle-approved mutant)."""

    case_id: str
    domain: str
    malicious: bool
    outcome: AssuranceOutcome
    parent_id: str | None = None
    mutator: str | None = None
    category: str | None = None
    role: str = "original"  # original | mutant | camouflage | hard-negative


@dataclass(frozen=True)
class MetricValue:
    successes: int
    n: int
    value: float | None
    ci_low: float | None
    ci_high: float | None


@dataclass
class ScoreCard:
    metrics: dict[str, MetricValue]
    overall: float | None
    grade: str
    confidence: str
    incomplete: int = 0
    evaluated: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def wilson(successes: int, n: int, z: float = 1.96) -> MetricValue:
    if n == 0:
        return MetricValue(0, 0, None, None, None)
    p = successes / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return MetricValue(successes, n, round(p, 4), round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def grade_for(score: float) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


def _conditional(records: list[RunRecord], by_id: dict[str, RunRecord], select, good: AssuranceOutcome) -> tuple[int, int]:
    hits = n = 0
    for r in records:
        if not select(r) or r.outcome not in SCORED:
            continue
        parent = by_id.get(r.parent_id or "")
        if parent is None or parent.outcome != good:
            continue  # parent already handled wrongly or not run: baseline metric covers it
        n += 1
        hits += r.outcome == good
    return hits, n


def compute_scorecard(records: list[RunRecord]) -> ScoreCard:
    originals = [r for r in records if r.role == "original"]
    by_id = {r.case_id: r for r in originals}
    incomplete = sum(1 for r in records if r.outcome not in SCORED)
    evaluated = len(records) - incomplete

    def count(select, good: AssuranceOutcome, bad: AssuranceOutcome) -> tuple[int, int]:
        ok = sum(1 for r in originals if select(r) and r.outcome == good)
        ko = sum(1 for r in originals if select(r) and r.outcome == bad)
        return ok, ok + ko

    metrics: dict[str, MetricValue] = {}
    metrics["recall"] = wilson(*count(lambda r: r.malicious, AssuranceOutcome.DETECTED, AssuranceOutcome.NOT_DETECTED))
    metrics["specificity"] = wilson(*count(lambda r: not r.malicious, AssuranceOutcome.PASS, AssuranceOutcome.FAIL))

    for key, category in (
        ("semantic_robustness", "semantic"),
        ("structural_robustness", "structural"),
        ("cross_file_robustness", "cross_file"),
        ("obfuscation_robustness", "obfuscation"),
    ):
        metrics[key] = wilson(
            *_conditional(
                records, by_id,
                lambda r, c=category: r.role == "mutant" and r.malicious and r.category == c,
                AssuranceOutcome.DETECTED,
            )
        )

    camo_hit, camo_n = _conditional(
        records, by_id, lambda r: r.role == "camouflage" and r.malicious, AssuranceOutcome.DETECTED
    )
    neg_hit, neg_n = _conditional(
        records, by_id, lambda r: r.role == "hard-negative" and not r.malicious, AssuranceOutcome.PASS
    )
    metrics["negative_context_safety"] = wilson(camo_hit + neg_hit, camo_n + neg_n)

    notes: list[str] = []
    active = {k: v for k, v in metrics.items() if v.n > 0 and v.value is not None}
    for key, mv in metrics.items():
        if mv.n == 0:
            notes.append(f"{key}: no evidence (excluded from overall)")
        elif mv.n < MIN_SAMPLES_PER_METRIC:
            notes.append(f"{key}: only n={mv.n} samples (< {MIN_SAMPLES_PER_METRIC})")

    if not active:
        return ScoreCard(metrics, None, "INCOMPLETE", "none", incomplete, evaluated, notes + ["no scored results"])

    total_w = sum(WEIGHTS[k] for k in active)
    # Weighted geometric mean: a zero in any metric (e.g. a scanner that never detects anything)
    # drives the overall score to zero instead of being averaged away by the other metrics.
    if any((v.value or 0.0) <= 0.0 for v in active.values()):
        overall = 0.0
    else:
        overall = round(math.exp(sum(WEIGHTS[k] * math.log(v.value) for k, v in active.items()) / total_w), 4)

    if records and incomplete / len(records) > MAX_INCOMPLETE_FRACTION:
        notes.append(f"{incomplete}/{len(records)} runs incomplete (> {MAX_INCOMPLETE_FRACTION:.0%}): no grade issued")
        return ScoreCard(metrics, overall, "INCOMPLETE", "none", incomplete, evaluated, notes)

    # Recall and specificity are gating metrics: no grade may exceed the weaker of the two.
    base = [metrics["recall"], metrics["specificity"]]
    if any(m.n == 0 or m.value is None for m in base):
        notes.append("recall or specificity has no evidence: no grade issued")
        return ScoreCard(metrics, overall, "INCOMPLETE", "none", incomplete, evaluated, notes)
    ceiling = min(m.value for m in base)  # type: ignore[type-var]
    if ceiling < overall:
        notes.append(f"overall capped from {overall:.4f} to {ceiling:.4f} by the weaker of recall/specificity")
        overall = ceiling

    low = evaluated < MIN_TOTAL_SAMPLES or any(v.n < MIN_SAMPLES_PER_METRIC for v in active.values())
    if len(active) < len(WEIGHTS):
        notes.append("overall computed over a subset of metrics (some had no evidence)")
    return ScoreCard(metrics, overall, grade_for(overall), "low" if low else "sufficient", incomplete, evaluated, notes)
