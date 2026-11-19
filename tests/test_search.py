"""Adaptive hunting and delta-debugging minimization."""

import pytest

from rantanplan.adapters.reference import get_reference_adapters
from rantanplan.corpus_builder import build_corpus
from rantanplan.models import RunProfile
from rantanplan.oracle import MetamorphicOracle
from rantanplan.search import SearchEngine, ddmin

BY_ID = {c.id: c for c in build_corpus()}
ADAPTERS = {a.identity().name: a for a in get_reference_adapters()}
PROFILE = RunProfile()


def test_ddmin_finds_one_minimal_subset():
    assert ddmin(list("abcdefgh"), lambda s: "c" in s and "g" in s) == ["c", "g"]
    assert ddmin(["x"], lambda s: True) == ["x"]


def test_hunt_false_negative_finds_only_oracle_valid_evasions():
    engine = SearchEngine(ADAPTERS["mock-naive"], seed=3)
    case = BY_ID["exfil-prose-00"]
    found = engine.hunt_false_negative(case, PROFILE, max_iterations=60)
    assert found
    oracle = MetamorphicOracle()
    for mutant, result in found:
        assert result.outcome.value == "NOT_DETECTED"
        assert oracle.check(case, mutant).valid


def test_strict_target_cannot_be_evaded():
    engine = SearchEngine(ADAPTERS["mock-strict"], seed=3)
    assert engine.hunt_false_negative(BY_ID["exfil-prose-00"], PROFILE, max_iterations=80) == []


def test_hunt_false_positive_finds_paranoid_flagging_and_rejects_malicious_input():
    engine = SearchEngine(ADAPTERS["mock-paranoid"], seed=3)
    found = engine.hunt_false_positive(BY_ID["exfil-benign-00"], PROFILE, max_iterations=20)
    assert found
    with pytest.raises(ValueError):
        engine.hunt_false_positive(BY_ID["exfil-prose-00"], PROFILE)


def test_search_is_reproducible_for_a_seed():
    def run():
        e = SearchEngine(ADAPTERS["mock-naive"], seed=9)
        return [m.id for m, _ in e.hunt_false_negative(BY_ID["inject-00"], PROFILE, 40)]

    assert run() == run()


def test_minimize_shrinks_and_preserves_outcome_and_label():
    engine = SearchEngine(ADAPTERS["mock-strict"], seed=1)
    case = BY_ID["exfil-prose-00"]
    padded = case.model_copy(deep=True)
    padded.files[0]["content"] += "\n".join(f"\nFiller line {i} about the weather." for i in range(10))
    reduced = engine.minimize(padded, PROFILE)
    assert reduced.id == padded.id
    before = len(padded.files[0]["content"].splitlines())
    after = len(reduced.files[0]["content"].splitlines())
    assert after < before and after <= 3
    assert "attacker.example.com" in reduced.files[0]["content"]


def test_minimize_drops_unneeded_files():
    engine = SearchEngine(ADAPTERS["mock-strict"], seed=1)
    case = BY_ID["exfil-script-00"].model_copy(deep=True)
    case.files.append({"path": "NOTES.md", "content": "Nothing relevant here."})
    reduced = engine.minimize(case, PROFILE)
    assert all(f["path"] != "NOTES.md" for f in reduced.files)
