"""
Adaptive evasion search and delta-debugging minimization.

* ``hunt_false_negative`` mutates a malicious case (chains of up to ``max_depth`` mutations),
  keeps only oracle-approved mutants, and reports those the target misses.
* ``hunt_false_positive`` does the same for a benign case and reports mutants the target flags.
* ``minimize`` shrinks a case with classic ddmin while the target's outcome *and* the reference
  label stay unchanged, giving a minimal reproducer.

Every mutant is checked against the **root** case, so drift cannot accumulate along a chain.
"""

from __future__ import annotations

import copy
import random
from collections.abc import Callable, Sequence

from rantanplan.assurance import execute_case
from rantanplan.models import AssuranceOutcome, RichNormalizedResult, RunProfile, TestCase
from rantanplan.mutators import ALL_MUTATORS, Mutator
from rantanplan.oracle import MetamorphicOracle
from rantanplan.semantics import analyze_files
from rantanplan.target_hierarchy import TargetAdapter


def ddmin(units: Sequence[str], test: Callable[[list[str]], bool]) -> list[str]:
    """Zeller's ddmin: smallest sub-sequence of ``units`` (1-minimal) for which ``test`` holds."""
    current = list(units)
    n = 2
    while len(current) >= 2:
        chunk = max(1, len(current) // n)
        subsets = [current[i : i + chunk] for i in range(0, len(current), chunk)]
        reduced = False
        for i, subset in enumerate(subsets):
            complement = [u for j, s in enumerate(subsets) if j != i for u in s]
            if complement and test(complement):
                current, n, reduced = complement, max(n - 1, 2), True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    return current


class SearchEngine:
    """Adaptive search against one target."""

    def __init__(
        self,
        adapter: TargetAdapter,
        seed: int = 42151,
        mutators: Sequence[Mutator] | None = None,
        max_depth: int = 3,
    ):
        self.adapter = adapter
        self.rng = random.Random(seed)
        self.mutators = list(mutators) if mutators is not None else list(ALL_MUTATORS)
        self.max_depth = max_depth
        self.oracle = MetamorphicOracle()

    def _run(self, case: TestCase, profile: RunProfile) -> RichNormalizedResult:
        return execute_case(self.adapter, case, profile)

    def _search(
        self,
        root: TestCase,
        profile: RunProfile,
        max_iterations: int,
        hit: AssuranceOutcome,
        keep_exploring: AssuranceOutcome,
    ) -> list[tuple[TestCase, RichNormalizedResult]]:
        found: list[tuple[TestCase, RichNormalizedResult]] = []
        frontier: list[tuple[TestCase, int]] = [(root, 0)]
        seen = {tuple(f.get("content", "") for f in root.files)}
        for _ in range(max_iterations):
            parent, depth = self.rng.choice(frontier)
            mutator = self.rng.choice(self.mutators)
            mutant = mutator.apply(parent, random.Random(self.rng.random()))
            if mutant is None:
                continue
            key = tuple(f.get("content", "") for f in mutant.files)
            if key in seen:
                continue
            seen.add(key)
            if not self.oracle.check(root, mutant).valid:
                continue
            result = self._run(mutant, profile)
            if result.outcome == hit:
                found.append((mutant, result))
            elif result.outcome == keep_exploring and depth + 1 < self.max_depth:
                frontier.append((mutant, depth + 1))
        return found

    def hunt_false_negative(
        self, case: TestCase, profile: RunProfile, max_iterations: int = 10
    ) -> list[tuple[TestCase, RichNormalizedResult]]:
        """Valid mutants of a malicious case that the target does NOT detect."""
        return self._search(case, profile, max_iterations, AssuranceOutcome.NOT_DETECTED, AssuranceOutcome.DETECTED)

    def hunt_false_positive(
        self, case: TestCase, profile: RunProfile, max_iterations: int = 10
    ) -> list[tuple[TestCase, RichNormalizedResult]]:
        """Valid mutants of a benign case that the target flags. ``case`` must be benign."""
        if case.ground_truth.get("malicious", False):
            raise ValueError(f"hunt_false_positive needs a benign case, got malicious case '{case.id}'")
        return self._search(case, profile, max_iterations, AssuranceOutcome.FAIL, AssuranceOutcome.PASS)

    def minimize(self, case: TestCase, profile: RunProfile) -> TestCase:
        """ddmin over files, then over the lines of each file, preserving target outcome and label."""
        baseline = self._run(case, profile).outcome
        label = bool(case.ground_truth.get("malicious", False))
        minimized = copy.deepcopy(case)

        def holds(candidate: TestCase) -> bool:
            if analyze_files(candidate.files).malicious != label:
                return False
            return self._run(candidate, profile).outcome == baseline

        def with_files(files: list[dict[str, str]]) -> TestCase:
            c = copy.deepcopy(minimized)
            c.files = files
            return c

        # 1. drop whole files
        idx = ddmin([str(i) for i in range(len(minimized.files))], lambda ids: holds(with_files([minimized.files[int(i)] for i in ids])))
        minimized.files = [minimized.files[int(i)] for i in idx]

        # 2. drop lines inside each file
        for fi in range(len(minimized.files)):
            lines = minimized.files[fi].get("content", "").split("\n")

            def line_test(sub: list[str], fi: int = fi) -> bool:
                files = copy.deepcopy(minimized.files)
                files[fi]["content"] = "\n".join(sub)
                return holds(with_files(files))

            kept = ddmin(lines, line_test)
            minimized.files[fi] = {**minimized.files[fi], "content": "\n".join(kept)}
        return minimized
