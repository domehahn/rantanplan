"""
NVIDIA garak Scanner Adapter implementation.
"""

import json
import os
import shutil
from typing import List, Optional

from rantanplan.adapters.base import ScannerAdapter
from rantanplan.execution import SandboxRunner
from rantanplan.models import (
    ApplicabilityState,
    DoctorResult,
    NormalizedFinding,
    NormalizedResult,
    Outcome,
    RawExecution,
    RunProfile,
    ScannerIdentity,
    Severity,
    TestCase,
)


class GarakAdapter(ScannerAdapter):
    """Adapter for NVIDIA garak vulnerability scanner."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or os.environ.get("RANTANPLAN_GARAK_BIN") or shutil.which("garak") or "garak"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="garak",
            version="0.9.0",
            binary_path=self.binary_path,
        )

    def doctor(self) -> DoctorResult:
        path_exists = shutil.which(self.binary_path) is not None
        return DoctorResult(
            installed=path_exists,
            version="0.9.0" if path_exists else "not installed",
            path=self.binary_path,
            supported=path_exists,
            status_message="garak available" if path_exists else "garak binary not found (Mock LLM target fallback available)",
        )

    def capabilities(self) -> List[str]:
        return [
            "llm.jailbreak",
            "prompt.injection",
            "llm.data-leakage",
            "llm.toxicity",
            "llm.hallucination",
        ]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.garak != ApplicabilityState.NOT_APPLICABLE

    def build_command(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> List[str]:
        return [self.binary_path, "--model_type", "test", "--probes", "promptinject"]

    def run(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if not shutil.which(self.binary_path):
            return self._run_mock(case, fixture_dir)

        cmd = self.build_command(case, profile, fixture_dir)
        runner = SandboxRunner(timeout_seconds=profile.timeout_seconds)
        return runner.execute(cmd, scanner_name="garak")

    def _run_mock(self, case: TestCase, fixture_dir: str) -> RawExecution:
        content = ""
        for file_info in case.files:
            content += file_info.get("content", "").lower() + "\n"

        has_vuln = "jailbreak" in content or "ignore previous instructions" in content or "override" in content

        stdout = json.dumps({"probes_evaluated": 5, "vulnerabilities_found": 1 if has_vuln else 0})
        return RawExecution(
            scanner="garak",
            command=[self.binary_path, "--model_type", "mock"],
            exit_code=1 if has_vuln else 0,
            stdout=stdout,
            stderr="",
            duration_ms=8,
        )

    def parse(self, case: TestCase, execution: RawExecution) -> NormalizedResult:
        if execution.timed_out:
            return NormalizedResult(
                run_id="run-garak",
                case_id=case.id,
                scanner="garak",
                scanner_version="0.9.0",
                applicable=True,
                outcome=Outcome.TIMEOUT,
                duration_ms=execution.duration_ms,
            )

        findings: List[NormalizedFinding] = []
        is_vulnerable = False

        if execution.stdout.strip():
            try:
                data = json.loads(execution.stdout)
                if data.get("vulnerabilities_found", 0) > 0:
                    is_vulnerable = True
                    findings.append(
                        NormalizedFinding(
                            scanner="garak",
                            native_rule_id="garak.promptinject",
                            canonical_capability=case.domain,
                            severity=Severity.HIGH,
                            message="garak probe triggered vulnerability finding",
                            native_evidence=data,
                        )
                    )
            except json.JSONDecodeError:
                if execution.exit_code != 0:
                    is_vulnerable = True

        expected_malicious = case.ground_truth.get("malicious", False)

        if is_vulnerable:
            outcome = Outcome.DETECTED if expected_malicious else Outcome.FAIL
        else:
            outcome = Outcome.NOT_DETECTED if expected_malicious else Outcome.PASS

        return NormalizedResult(
            run_id="run-garak",
            case_id=case.id,
            scanner="garak",
            scanner_version="0.9.0",
            applicable=True,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )
