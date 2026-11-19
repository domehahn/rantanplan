"""
Reference (calibration) targets.

These are *not* scanners to be trusted. They are fixed points that anchor the scoring scale:

* ``mock-blind``    never flags anything          -> must score recall 0
* ``mock-paranoid`` flags every suspicious word   -> must score specificity ~0 on hard negatives
* ``mock-naive``    keyword matching              -> must be evaded by mutation
* ``mock-strict``   uses the reference semantics  -> calibration ceiling (shares the oracle's
                                                     definition of meaning, so it is circular by
                                                     design and says nothing about real scanners)
"""

from __future__ import annotations

import json
from collections.abc import Callable

from rantanplan.lexicon import (
    DESTINATION_PATTERNS,
    EXEC_PATTERNS,
    INJECTION_PATTERNS,
    SOURCE_PATTERNS,
    TRANSFER_VERBS,
)
from rantanplan.models import (
    AssuranceOutcome,
    DoctorResult,
    RawExecution,
    RichNormalizedResult,
    RunProfile,
    ScannerIdentity,
    TestCase,
)
from rantanplan.semantics import analyze_files
from rantanplan.target_hierarchy import ArtifactScannerAdapter

CAPABILITIES = [
    "secret.exfiltration",
    "prompt.injection",
    "code.execution",
    "artifact.obfuscation",
    "mcp.tool-poisoning",
]


def _text(case: TestCase) -> str:
    return "\n".join(f.get("content", "") for f in case.files)


def detect_naive(case: TestCase) -> bool:
    t = _text(case).lower()
    return (
        ("secret" in t and "send" in t)
        or "attacker.example.com" in t
        or "ignore previous instructions" in t
        or "rm -rf /" in t
        or "hidden instruction" in t
    )


def detect_strict(case: TestCase) -> bool:
    return analyze_files(case.files).malicious


def detect_paranoid(case: TestCase) -> bool:
    t = _text(case)
    groups = (SOURCE_PATTERNS, TRANSFER_VERBS, DESTINATION_PATTERNS, INJECTION_PATTERNS, EXEC_PATTERNS)
    return any(p.search(t) for g in groups for p in g)


def detect_blind(case: TestCase) -> bool:
    return False


class ReferenceAdapter(ArtifactScannerAdapter):
    """In-process calibration target; never spawns a subprocess."""

    def __init__(self, name: str, detector: Callable[[TestCase], bool], description: str):
        self._name = name
        self._detector = detector
        self._description = description

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name=self._name, version="reference-1", binary_path=f"builtin:{self._name}")

    def doctor(self) -> DoctorResult:
        return DoctorResult(
            installed=True, version="reference-1", path=f"builtin:{self._name}", supported=True,
            status_message=f"Built-in calibration target: {self._description}",
        )

    def capabilities(self) -> list[str]:
        return list(CAPABILITIES)

    def supports(self, case: TestCase) -> bool:
        return case.domain in CAPABILITIES

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        flagged = self._detector(case)
        return RawExecution(
            scanner=self._name,
            command=[f"builtin:{self._name}"],
            exit_code=1 if flagged else 0,
            stdout=json.dumps({"vulnerable": flagged}),
            stderr="",
            duration_ms=1,
        )

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        flagged = execution.exit_code == 1
        malicious = bool(case.ground_truth.get("malicious", False))
        if flagged:
            outcome = AssuranceOutcome.DETECTED if malicious else AssuranceOutcome.FAIL
        else:
            outcome = AssuranceOutcome.NOT_DETECTED if malicious else AssuranceOutcome.PASS
        return RichNormalizedResult(
            run_id=f"run-{self._name}",
            case_id=case.id,
            target_name=self._name,
            target_version="reference-1",
            outcome=outcome,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        return self.parse(case, self.execute(case, profile, fixture_dir))


def get_reference_adapters() -> list[ReferenceAdapter]:
    return [
        ReferenceAdapter("mock-blind", detect_blind, "never flags (recall floor)"),
        ReferenceAdapter("mock-paranoid", detect_paranoid, "flags every suspicious term (specificity floor)"),
        ReferenceAdapter("mock-naive", detect_naive, "keyword matching"),
        ReferenceAdapter("mock-strict", detect_strict, "reference semantics (calibration ceiling, circular by design)"),
    ]
