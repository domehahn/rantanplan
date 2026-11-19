"""End-to-end assurance runs and the calibration of the scoring scale."""

import json

import pytest

from rantanplan.adapters.reference import get_reference_adapters
from rantanplan.assurance import execute_case, run_assurance
from rantanplan.corpus_builder import build_corpus
from rantanplan.models import AssuranceOutcome, RunProfile
from rantanplan.mutators import get_mutators
from rantanplan.target_hierarchy import ArtifactScannerAdapter

CASES = build_corpus()
ADAPTERS = {a.identity().name: a for a in get_reference_adapters()}


@pytest.fixture(scope="module")
def reports():
    return {name: run_assurance(a, CASES, seed=7, mutants_per_case=3) for name, a in ADAPTERS.items()}


def test_scale_is_calibrated(reports):
    grades = {n: r.scorecard for n, r in reports.items()}
    assert grades["mock-blind"].grade == "F"
    assert grades["mock-strict"].grade == "A+"
    assert grades["mock-blind"].overall <= grades["mock-naive"].overall < grades["mock-strict"].overall
    assert grades["mock-paranoid"].overall < grades["mock-strict"].overall
    assert grades["mock-paranoid"].metrics["specificity"].value < 0.7


def test_mutation_exposes_the_naive_scanner(reports):
    naive, strict = reports["mock-naive"], reports["mock-strict"]
    assert naive.evasions and not strict.evasions
    assert naive.scorecard.metrics["obfuscation_robustness"].value < 0.8
    assert {e.category for e in naive.evasions} >= {"obfuscation"}


def test_results_are_reproducible_for_a_seed():
    a = run_assurance(ADAPTERS["mock-naive"], CASES, seed=11, mutants_per_case=2)
    b = run_assurance(ADAPTERS["mock-naive"], CASES, seed=11, mutants_per_case=2)
    c = run_assurance(ADAPTERS["mock-naive"], CASES, seed=12, mutants_per_case=2)
    assert a.to_dict() == b.to_dict()
    assert [r.case_id for r in a.records] != [r.case_id for r in c.records] or a.to_dict() != c.to_dict()


def test_every_scored_mutant_passed_the_oracle(reports):
    r = reports["mock-strict"]
    assert sum(r.discarded.values()) / max(1, sum(1 for x in r.records if x.role != "original")) < 0.01
    assert all(rec.parent_id for rec in r.records if rec.role != "original")


def test_report_is_json_serialisable(reports):
    json.dumps(reports["mock-naive"].to_dict())


def test_cases_outside_scope_are_skipped():
    from rantanplan.models import TestCase

    odd = TestCase(id="lic", title="t", domain="license.policy", kind="artifact", ground_truth={"malicious": True}, files=[])
    r = run_assurance(ADAPTERS["mock-strict"], [odd, *CASES[:2]], seed=1)
    assert r.skipped_cases == 1


def test_mutator_subset_is_respected():
    r = run_assurance(ADAPTERS["mock-naive"], CASES, mutators=get_mutators(["lexical"]), seed=1)
    assert {x.mutator for x in r.records if x.mutator} == {"lexical"}


class Exploding(ArtifactScannerAdapter):
    def identity(self):
        return ADAPTERS["mock-strict"].identity()

    def doctor(self):
        return ADAPTERS["mock-strict"].doctor()

    def capabilities(self):
        return ["secret.exfiltration"]

    def supports(self, case):
        return True

    def execute(self, case, profile, fixture_dir):
        raise RuntimeError("adapter bug")

    def parse(self, case, execution):
        raise AssertionError

    def scan_artifact(self, case, profile, fixture_dir):
        raise AssertionError


def test_adapter_exceptions_become_incomplete_never_a_verdict():
    res = execute_case(Exploding(), CASES[0], RunProfile())
    assert res.outcome == AssuranceOutcome.INCOMPLETE
    r = run_assurance(Exploding(), CASES[:10], seed=1)
    assert r.scorecard.grade == "INCOMPLETE"
