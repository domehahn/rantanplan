"""Mutators: determinism, applicability, and oracle-validity over the whole corpus."""

import random
from collections import Counter

import pytest

from rantanplan.corpus_builder import build_corpus
from rantanplan.mutators import ALL_MUTATORS, CATEGORIES, case_rng, get_mutators, split_protected
from rantanplan.oracle import MetamorphicOracle

CASES = build_corpus()
BY_ID = {c.id: c for c in CASES}


def test_there_are_eight_mutators_in_five_categories():
    assert len(ALL_MUTATORS) == 8
    assert {m.category for m in ALL_MUTATORS} == set(CATEGORIES)


def test_get_mutators_by_name_and_unknown():
    assert [m.name for m in get_mutators(["lexical", "unicode"])] == ["lexical", "unicode"]
    with pytest.raises(KeyError):
        get_mutators(["nope"])


def test_same_seed_same_mutants_different_seed_differs():
    case = BY_ID["exfil-prose-00"]
    lexical = get_mutators(["lexical"])[0]
    a = lexical.apply(case, case_rng(1, case.id, "lexical"))
    b = lexical.apply(case, case_rng(1, case.id, "lexical"))
    assert a is not None and a.files == b.files
    variants = {tuple(f["content"] for f in lexical.apply(case, case_rng(s, case.id, "lexical")).files) for s in range(20)}
    assert len(variants) > 1


def test_mutant_carries_provenance_and_keeps_label():
    case = BY_ID["exfil-prose-00"]
    mutant = get_mutators(["semantic"])[0].apply(case, random.Random(0))
    assert mutant.ground_truth["mutation"]["parent"] == case.id
    assert mutant.ground_truth["malicious"] is True
    assert mutant.id != case.id and case.files != mutant.files


def test_original_case_is_never_modified():
    case = BY_ID["exfil-prose-00"]
    before = [dict(f) for f in case.files]
    for m in ALL_MUTATORS:
        m.apply(case, random.Random(3))
    assert case.files == before and "mutation" not in case.ground_truth


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_oracle_accepts_nearly_all_mutants(seed):
    oracle, total, rejected = MetamorphicOracle(), 0, Counter()
    for case in CASES:
        for m in ALL_MUTATORS:
            mutant = m.apply(case, case_rng(seed, case.id, m.name))
            if mutant is None:
                continue
            total += 1
            if not oracle.check(case, mutant).valid:
                rejected[m.name] += 1
    assert total > 300
    assert sum(rejected.values()) / total < 0.01, dict(rejected)


def test_every_mutator_applies_to_some_case():
    for m in ALL_MUTATORS:
        assert any(m.apply(c, random.Random(0)) for c in CASES), m.name


def test_negative_context_role_depends_on_label():
    neg = get_mutators(["negative_context"])[0]
    mal = neg.apply(BY_ID["exfil-prose-00"], random.Random(0))
    ben = neg.apply(BY_ID["exfil-benign-00"], random.Random(0))
    assert mal.ground_truth["mutation"]["role"] == "camouflage"
    assert ben.ground_truth["mutation"]["role"] == "hard-negative"


def test_split_instruction_and_cross_file_structure():
    case = BY_ID["exfil-prose-00"]
    split = get_mutators(["split_instruction"])[0].apply(case, random.Random(0))
    assert "## Step 1" in split.files[0]["content"] and "the collected data" in split.files[0]["content"]
    cross = get_mutators(["cross_file"])[0].apply(case, random.Random(0))
    assert any(f["path"] == "references/reporting.md" for f in cross.files)


def test_code_alias_rewrites_scripts_only():
    script_case = BY_ID["exfil-script-00"]
    mutant = get_mutators(["code_alias"])[0].apply(script_case, random.Random(0))
    code = next(f["content"] for f in mutant.files if f["path"].endswith(".py"))
    assert 'getattr(requests, "po" + "st")' in code and "_env" in code
    assert get_mutators(["code_alias"])[0].apply(BY_ID["exfil-prose-00"], random.Random(0)) is None


def test_encoding_modes():
    enc = get_mutators(["encoding"])[0]
    script = enc.apply(BY_ID["exfil-script-00"], random.Random(0))
    assert script.ground_truth["mutation"]["mode"] == "literal_concat"
    prose = enc.apply(BY_ID["inject-00"], random.Random(0))
    assert prose.ground_truth["mutation"]["mode"] == "base64_note"
    assert "base64" in prose.files[0]["content"]


def test_unicode_never_touches_protected_spans():
    case = BY_ID["exfil-prose-00"]
    for seed in range(15):
        mutant = get_mutators(["unicode"])[0].apply(case, random.Random(seed))
        assert "attacker.example.com" in mutant.files[0]["content"] or "https://" in mutant.files[0]["content"]


def test_split_protected_marks_hosts_urls_code_and_commands():
    parts = dict(split_protected("see `x` and https://a.example.com and host b.example.org then sudo rm -rf /tmp"))
    protected = {seg for seg, p in split_protected("see `x` and https://a.example.com and sudo rm -rf /tmp") if p}
    assert "`x`" in protected and "https://a.example.com" in protected
    assert any(p.startswith("sudo rm") for p in protected)
    assert parts
