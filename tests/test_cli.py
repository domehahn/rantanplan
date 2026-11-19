"""CLI smoke and behaviour tests (offline, calibration targets only)."""

import json

import pytest
from typer.testing import CliRunner

from rantanplan.cli import app

runner = CliRunner()


def invoke(*args):
    return runner.invoke(app, list(args), catch_exceptions=False)


def test_doctor_and_list():
    assert invoke("doctor").exit_code == 0
    out = invoke("list", "scanners").output
    assert "mock-strict" in out and "skil" in out
    assert "secret.exfiltration" in invoke("list", "capabilities").output
    assert "exfil-prose-00" in invoke("list", "cases").output
    assert "secret.exfiltration" in invoke("corpus", "list").output


def test_verify_ground_truth_passes_on_committed_corpus():
    res = invoke("verify-ground-truth")
    assert res.exit_code == 0 and "Successfully verified" in res.output


def test_test_scanner_json_is_reproducible(tmp_path):
    out = tmp_path / "r.json"
    args = ["test", "scanner", "--target", "mock-naive", "--seed", "5", "--format", "json", "--output", str(out)]
    assert invoke(*args).exit_code == 0
    first = json.loads(out.read_text())
    invoke(*args)
    assert json.loads(out.read_text()) == first
    assert first["target"] == "mock-naive" and first["scorecard"]["grade"] == "F"


@pytest.mark.parametrize("fmt", ["dashboard", "markdown", "html", "json"])
def test_report_formats(fmt):
    res = invoke("test", "scanner", "--target", "mock-strict", "--format", fmt, "--mutants-per-case", "1")
    assert res.exit_code == 0 and "A+" in res.output


def test_unknown_format_and_target_fail():
    assert runner.invoke(app, ["test", "scanner", "--target", "mock-strict", "--format", "xml"]).exit_code != 0
    assert runner.invoke(app, ["test", "scanner", "--target", "does-not-exist"]).exit_code != 0


def test_compare_writes_markdown(tmp_path):
    out = tmp_path / "c.md"
    assert invoke("compare", "--targets", "mock-blind,mock-strict", "--format", "markdown", "--output", str(out), "--mutants-per-case", "1").exit_code == 0
    text = out.read_text()
    assert "mock-blind" in text and "mock-strict" in text and "Recall" in text


def test_mutate_shows_oracle_verdicts():
    res = invoke("mutate", "--case", "exfil-prose-00")
    assert "valid" in res.output and "split_instruction" in res.output
    assert runner.invoke(app, ["mutate", "--case", "nope"]).exit_code == 2


def test_hunt_and_minimize():
    res = invoke("hunt", "--target", "mock-naive", "--case", "exfil-prose-00", "--iterations", "30")
    assert "Hunt complete" in res.output
    res = invoke("hunt", "--target", "mock-paranoid", "--mode", "false-positive", "--case", "exfil-benign-00", "--iterations", "10")
    assert "false-positive" in res.output
    assert runner.invoke(app, ["hunt", "--mode", "weird"]).exit_code != 0
    assert runner.invoke(app, ["hunt", "--case", "nope"]).exit_code == 2
    res = invoke("minimize", "--target", "mock-strict", "--case", "exfil-prose-00")
    assert "Minimized exfil-prose-00" in res.output
    assert runner.invoke(app, ["minimize", "--case", "nope"]).exit_code == 2


def test_gate_pass_fail_and_confidence(tmp_path):
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    invoke("test", "scanner", "--target", "mock-strict", "--format", "json", "--output", str(good))
    invoke("test", "scanner", "--target", "mock-naive", "--format", "json", "--output", str(bad))
    assert runner.invoke(app, ["gate", "--results", str(good), "--min-grade", "A"]).exit_code == 0
    assert runner.invoke(app, ["gate", "--results", str(bad), "--min-grade", "B"]).exit_code == 1
    data = json.loads(good.read_text())
    data["scorecard"]["confidence"] = "low"
    low = tmp_path / "low.json"
    low.write_text(json.dumps(data))
    assert runner.invoke(app, ["gate", "--results", str(low), "--min-grade", "A"]).exit_code == 1
    assert runner.invoke(app, ["gate", "--results", str(low), "--min-grade", "A", "--allow-low-confidence"]).exit_code == 0


def test_gate_accepts_multi_target_results(tmp_path):
    out = tmp_path / "multi.json"
    invoke("compare", "--targets", "mock-strict,mock-blind", "--format", "json", "--output", str(out), "--mutants-per-case", "1")
    assert runner.invoke(app, ["gate", "--results", str(out), "--min-grade", "B"]).exit_code == 1


def test_export_regression_writes_loadable_cases(tmp_path):
    res = invoke("export", "regression", "--target", "mock-naive", "--output", str(tmp_path))
    assert "Exported" in res.output
    files = list(tmp_path.glob("*.yaml"))
    assert files
    from rantanplan.corpus import load_corpus

    cases = load_corpus(tmp_path)
    assert cases and all(c.ground_truth["malicious"] for c in cases)


def test_corpus_build_regenerates_identical_files(tmp_path):
    from pathlib import Path

    invoke("corpus", "build", "--out", str(tmp_path))
    committed = {p.relative_to("corpus"): p.read_text() for p in Path("corpus").rglob("*.yaml")}
    rebuilt = {p.relative_to(tmp_path): p.read_text() for p in tmp_path.rglob("*.yaml")}
    assert committed == rebuilt, "corpus/ is stale: run `rantanplan corpus build`"


def test_suite_and_benchmark(tmp_path):
    assert "Calibration passed" in invoke("suite", "offline-core").output
    assert runner.invoke(app, ["suite", "garak"]).exit_code == 2
    out = tmp_path / "bench.md"
    invoke("benchmark", "--output", str(out), "--mutants-per-case", "1")
    text = out.read_text()
    assert "not a measurement of any real scanner" in text and "mock-strict" in text
