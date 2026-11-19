"""
Metamorphic oracle.

A mutant is only allowed to count against a scanner if the oracle can show that it still means
the same thing as its parent. The oracle compares the *reference semantics* of both versions:

* the ground-truth label (malicious / benign) is unchanged,
* the set of active capability signals is unchanged,
* literal indicators (hosts, destructive commands) are identical.

Anything else is *semantic drift* and the mutant is discarded and counted, never scored.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rantanplan.models import TestCase
from rantanplan.semantics import Analysis, analyze_files


@dataclass(frozen=True)
class OracleVerdict:
    valid: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


class MetamorphicOracle:
    """Verifies that a mutant preserves the invariants of its parent case."""

    MAX_GROWTH = 20  # a mutant may not grow beyond 20x the parent size (guards runaway mutations)

    def check(self, parent: TestCase, mutant: TestCase) -> OracleVerdict:
        reasons: list[str] = []
        label = bool(parent.ground_truth.get("malicious", False))

        if [f.get("content") for f in parent.files] == [f.get("content") for f in mutant.files]:
            return OracleVerdict(False, ("no-op: mutant is identical to parent",))

        before = analyze_files(parent.files)
        after = analyze_files(mutant.files)

        if before.malicious != label:
            reasons.append(
                f"parent label inconsistent with reference semantics (label={label}, analysis={before.malicious})"
            )
        if after.malicious != label:
            reasons.append(f"label flipped by mutation (expected malicious={label}, got {after.malicious})")
        if after.signals != before.signals:
            reasons.append(f"signals changed: {sorted(before.signals)} -> {sorted(after.signals)}")
        if after.indicators != before.indicators:
            reasons.append(
                f"indicators changed: {sorted(before.indicators ^ after.indicators)} differ between parent and mutant"
            )
        parent_size = sum(len(f.get("content", "")) for f in parent.files) or 1
        mutant_size = sum(len(f.get("content", "")) for f in mutant.files)
        if mutant_size > parent_size * self.MAX_GROWTH:
            reasons.append("mutant grew beyond size bound")

        return OracleVerdict(not reasons, tuple(reasons))

    def label_consistent(self, case: TestCase) -> OracleVerdict:
        """Check a corpus case: the declared label must agree with the reference semantics."""
        analysis: Analysis = analyze_files(case.files)
        label = bool(case.ground_truth.get("malicious", False))
        if analysis.malicious != label:
            reason = (
                f"declared malicious={label} but reference semantics say {analysis.malicious} "
                f"(signals={sorted(analysis.signals)})"
            )
            return OracleVerdict(False, (reason,))
        return OracleVerdict(True)
