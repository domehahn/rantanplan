"""Scoring: statistics, grading and the guards that stop a useless scanner from passing."""

import pytest

from rantanplan.models import AssuranceOutcome as O
from rantanplan.scoring import GRADES, RunRecord, compute_scorecard, grade_for, wilson


def rec(cid, malicious, outcome, role="original", parent=None, category=None, domain="secret.exfiltration"):
    return RunRecord(cid, domain, malicious, outcome, parent, "m" if parent else None, category, role)


def perfect(n_mal=20, n_ben=20, mutants=2):
    out = []
    for i in range(n_mal):
        out.append(rec(f"m{i}", True, O.DETECTED))
        for j, cat in enumerate(("semantic", "structural", "cross_file", "obfuscation")[:mutants + 2]):
            out.append(rec(f"m{i}~{j}", True, O.DETECTED, "mutant", f"m{i}", cat))
        out.append(rec(f"m{i}~c", True, O.DETECTED, "camouflage", f"m{i}", "negative_context"))
    for i in range(n_ben):
        out.append(rec(f"b{i}", False, O.PASS))
        out.append(rec(f"b{i}~h", False, O.PASS, "hard-negative", f"b{i}", "negative_context"))
    return out


def test_wilson_interval_properties():
    assert wilson(0, 0).value is None
    mv = wilson(8, 10)
    assert mv.value == 0.8 and mv.ci_low < 0.8 < mv.ci_high
    assert wilson(10, 10).ci_high == 1.0 and wilson(0, 10).ci_low == 0.0
    assert wilson(50, 100).ci_high - wilson(50, 100).ci_low < wilson(5, 10).ci_high - wilson(5, 10).ci_low


@pytest.mark.parametrize("score,expected", [(1.0, "A+"), (0.95, "A+"), (0.9, "A"), (0.72, "B-"), (0.5, "D"), (0.49, "F"), (0.0, "F")])
def test_grade_boundaries(score, expected):
    assert grade_for(score) == expected


def test_grades_are_monotonic():
    thresholds = [t for t, _ in GRADES]
    assert thresholds == sorted(thresholds, reverse=True)


def test_perfect_scanner_gets_a_plus_with_sufficient_confidence():
    sc = compute_scorecard(perfect())
    assert sc.grade == "A+" and sc.overall == 1.0 and sc.confidence == "sufficient"


def test_scanner_that_detects_nothing_fails():
    recs = [rec(f"m{i}", True, O.NOT_DETECTED) for i in range(20)] + [rec(f"b{i}", False, O.PASS) for i in range(20)]
    sc = compute_scorecard(recs)
    assert sc.grade == "F" and sc.overall == 0.0


def test_scanner_that_flags_everything_is_capped_by_specificity():
    recs = [rec(f"m{i}", True, O.DETECTED) for i in range(20)] + [rec(f"b{i}", False, O.FAIL) for i in range(20)]
    recs += [rec(f"b{i}~h", False, O.FAIL, "hard-negative", f"b{i}", "negative_context") for i in range(20)]
    sc = compute_scorecard(recs)
    assert sc.grade == "F"
    assert sc.metrics["specificity"].value == 0.0


def test_baseline_weakness_caps_good_robustness():
    recs = perfect()
    # miss 40% of the originals: robustness stays perfect (conditional) but the grade must not
    for i in range(8):
        recs = [r if r.case_id != f"m{i}" else rec(f"m{i}", True, O.NOT_DETECTED) for r in recs]
    sc = compute_scorecard(recs)
    assert sc.metrics["recall"].value == 0.6
    assert sc.overall <= 0.6 and any("capped" in n for n in sc.notes)


def test_robustness_is_conditional_on_parent_being_handled():
    recs = [rec("m0", True, O.NOT_DETECTED), rec("m0~0", True, O.NOT_DETECTED, "mutant", "m0", "semantic")]
    sc = compute_scorecard(recs)
    assert sc.metrics["semantic_robustness"].n == 0


def test_mutation_sensitivity_lowers_the_matching_category_only():
    recs = perfect()
    recs = [
        rec(r.case_id, True, O.NOT_DETECTED, "mutant", r.parent_id, "obfuscation") if r.category == "obfuscation" else r
        for r in recs
    ]
    sc = compute_scorecard(recs)
    assert sc.metrics["obfuscation_robustness"].value == 0.0
    assert sc.metrics["semantic_robustness"].value == 1.0
    assert sc.grade == "F"  # geometric mean: a zero metric zeroes the score


def test_incomplete_runs_are_excluded_and_too_many_withhold_the_grade():
    recs = perfect()
    some = recs + [rec(f"x{i}", True, O.INCOMPLETE) for i in range(3)]
    sc = compute_scorecard(some)
    assert sc.incomplete == 3 and sc.grade == "A+"
    many = recs + [rec(f"x{i}", True, O.INCOMPLETE) for i in range(200)]
    assert compute_scorecard(many).grade == "INCOMPLETE"


def test_no_evidence_for_baseline_withholds_grade():
    only_benign = [rec(f"b{i}", False, O.PASS) for i in range(20)]
    assert compute_scorecard(only_benign).grade == "INCOMPLETE"
    assert compute_scorecard([]).grade == "INCOMPLETE"


def test_small_samples_lower_confidence():
    recs = [rec(f"m{i}", True, O.DETECTED) for i in range(5)] + [rec(f"b{i}", False, O.PASS) for i in range(5)]
    sc = compute_scorecard(recs)
    assert sc.confidence == "low" and any("only n=" in n for n in sc.notes)


def test_scorecard_serialises():
    d = compute_scorecard(perfect()).to_dict()
    assert d["grade"] == "A+" and "recall" in d["metrics"]
