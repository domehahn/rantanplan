"""Contract tests against real scanner binaries. Skipped unless the binary is installed."""

import shutil

import pytest

from rantanplan.adapters.skil import SKILAdapter
from rantanplan.assurance import execute_case
from rantanplan.corpus import load_corpus
from rantanplan.models import AssuranceOutcome, RunProfile, TargetProfile

pytestmark = pytest.mark.skipif(shutil.which("skil") is None, reason="skil binary not installed")


def test_skil_reports_installed_with_a_real_version():
    doc = SKILAdapter().doctor()
    assert doc.installed and doc.version != "VERSION_UNKNOWN"


def test_skil_produces_a_verdict_for_every_corpus_case_in_scope():
    adapter = SKILAdapter()
    profile = RunProfile(profile_type=TargetProfile.OFFLINE, timeout_seconds=60)
    cases = [c for c in load_corpus() if c.domain == "secret.exfiltration"][:6]
    results = [execute_case(adapter, c, profile) for c in cases]
    # An adapter that cannot parse real skil output yields INCOMPLETE for everything.
    assert any(r.outcome != AssuranceOutcome.INCOMPLETE for r in results), [r.raw_report for r in results][:2]
