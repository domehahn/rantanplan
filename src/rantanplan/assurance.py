"""
Scanner assurance runner: corpus -> oracle-approved mutants -> target -> score card.
"""

from __future__ import annotations

import copy
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from rantanplan.corpus_builder import MUTATION_DOMAINS
from rantanplan.execution import create_temp_fixture_dir
from rantanplan.models import AssuranceOutcome, RichNormalizedResult, RunProfile, TestCase
from rantanplan.mutators import Mutator, case_rng, get_mutators
from rantanplan.oracle import MetamorphicOracle
from rantanplan.scoring import RunRecord, ScoreCard, compute_scorecard
from rantanplan.target_hierarchy import TargetAdapter

logger = logging.getLogger(__name__)


@dataclass
class Evasion:
    """A valid mutant that a scanner missed although it handled the parent correctly."""

    parent_id: str
    mutator: str
    category: str
    case: TestCase


@dataclass
class AssuranceReport:
    target: str
    version: str
    seed: int
    records: list[RunRecord]
    scorecard: ScoreCard
    evasions: list[Evasion] = field(default_factory=list)
    discarded: Counter = field(default_factory=Counter)  # (mutator) -> count rejected by the oracle
    discard_reasons: dict[str, str] = field(default_factory=dict)
    not_applicable: Counter = field(default_factory=Counter)
    skipped_cases: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "version": self.version,
            "seed": self.seed,
            "scorecard": self.scorecard.to_dict(),
            "records": len(self.records),
            "mutants_run": sum(1 for r in self.records if r.role != "original"),
            "discarded_by_oracle": dict(self.discarded),
            "discard_examples": self.discard_reasons,
            "not_applicable": dict(self.not_applicable),
            "skipped_cases": self.skipped_cases,
            "evasions": [
                {"parent": e.parent_id, "mutator": e.mutator, "category": e.category, "case_id": e.case.id}
                for e in self.evasions
            ],
        }


def execute_case(adapter: TargetAdapter, case: TestCase, profile: RunProfile) -> RichNormalizedResult:
    """Run one case through one adapter; adapter failures become INCOMPLETE, never a verdict."""
    tmp_dir, cleanup = create_temp_fixture_dir(case.files)
    try:
        raw = adapter.execute(case, profile, tmp_dir)
        return adapter.parse(case, raw)
    except Exception as exc:  # noqa: BLE001 - a broken adapter must not abort the whole assessment
        logger.warning("Adapter %s failed on %s: %s", adapter.identity().name, case.id, exc)
        return RichNormalizedResult(run_id="error", case_id=case.id, outcome=AssuranceOutcome.INCOMPLETE)
    finally:
        cleanup()


def run_assurance(
    adapter: TargetAdapter,
    cases: list[TestCase],
    mutators: list[Mutator] | None = None,
    seed: int = 42151,
    mutants_per_case: int = 1,
    profile: RunProfile | None = None,
    domains: tuple[str, ...] = MUTATION_DOMAINS,
) -> AssuranceReport:
    profile = profile or RunProfile()
    mutators = mutators if mutators is not None else get_mutators()
    oracle = MetamorphicOracle()
    ident = adapter.identity()

    records: list[RunRecord] = []
    evasions: list[Evasion] = []
    discarded: Counter = Counter()
    reasons: dict[str, str] = {}
    not_applicable: Counter = Counter()
    skipped = 0

    for case in cases:
        if case.domain not in domains or not adapter.supports(case):
            skipped += 1
            continue
        malicious = bool(case.ground_truth.get("malicious", False))
        base = execute_case(adapter, case, profile)
        records.append(RunRecord(case.id, case.domain, malicious, base.outcome))

        seen = {tuple(f.get("content", "") for f in case.files)}
        for mutator in mutators:
            for attempt in range(mutants_per_case):
                mutant = mutator.apply(case, case_rng(seed, case.id, mutator.name, attempt))
                if mutant is None:
                    not_applicable[mutator.name] += 1
                    continue
                key = tuple(f.get("content", "") for f in mutant.files)
                if key in seen:
                    continue
                seen.add(key)
                verdict = oracle.check(case, mutant)
                if not verdict.valid:
                    discarded[mutator.name] += 1
                    reasons.setdefault(mutator.name, f"{case.id}: {verdict.reasons[0]}")
                    continue
                role = "mutant"
                if mutator.category == "negative_context":
                    role = mutant.ground_truth["mutation"].get("role", "mutant")
                result = execute_case(adapter, mutant, profile)
                records.append(
                    RunRecord(mutant.id, case.domain, malicious, result.outcome, case.id, mutator.name, mutator.category, role)
                )
                if base.outcome == AssuranceOutcome.DETECTED and result.outcome == AssuranceOutcome.NOT_DETECTED:
                    evasions.append(Evasion(case.id, mutator.name, mutator.category, copy.deepcopy(mutant)))

    return AssuranceReport(
        target=ident.name,
        version=ident.version,
        seed=seed,
        records=records,
        scorecard=compute_scorecard(records),
        evasions=evasions,
        discarded=discarded,
        discard_reasons=reasons,
        not_applicable=not_applicable,
        skipped_cases=skipped,
    )
