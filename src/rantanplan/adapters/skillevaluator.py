"""
NVIDIA SkillEvaluator Scanner Adapter implementation.
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


class SkillEvaluatorAdapter(ScannerAdapter):
    """Adapter for NVIDIA SkillEvaluator."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or os.environ.get("RANTANPLAN_SKILLEVALUATOR_BIN") or shutil.which("skillevaluator") or "skillevaluator"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="skillevaluator",
            version="1.0.0",
            binary_path=self.binary_path,
        )

    def doctor(self) -> DoctorResult:
        path_exists = shutil.which(self.binary_path) is not None
        return DoctorResult(
            installed=path_exists,
            version="1.0.0" if path_exists else "not installed",
            path=self.binary_path,
            supported=path_exists,
            status_message="SkillEvaluator available" if path_exists else "SkillEvaluator binary not found (Mock fallback available)",
        )

    def capabilities(self) -> List[str]:
        return [
            "quality.structure",
            "quality.redundancy",
            "license.policy",
            "pii.exposure",
            "secret.exfiltration",
        ]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.skillevaluator != ApplicabilityState.NOT_APPLICABLE

    def build_command(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> List[str]:
        return [self.binary_path, "eval", "--path", fixture_dir, "--json"]

    def run(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if not shutil.which(self.binary_path):
            return self._run_mock(case, fixture_dir)

        cmd = self.build_command(case, profile, fixture_dir)
        runner = SandboxRunner(timeout_seconds=profile.timeout_seconds)
        return runner.execute(cmd, scanner_name="skillevaluator")

    def _run_mock(self, case: TestCase, fixture_dir: str) -> RawExecution:
        content = ""
        for file_info in case.files:
            content += file_info.get("content", "").lower() + "\n"

        has_vuln = "secret" in content and "send" in content or "duplicate" in content or "bad heading" in content

        stdout = json.dumps({"tier1_pass": not has_vuln, "tier2_dedup_pass": not has_vuln})
        return RawExecution(
            scanner="skillevaluator",
            command=[self.binary_path, "eval", fixture_dir],
            exit_code=1 if has_vuln else 0,
            stdout=stdout,
            stderr="",
            duration_ms=6,
        )

    def parse(self, case: TestCase, execution: RawExecution) -> NormalizedResult:
        if execution.timed_out:
            return NormalizedResult(
                run_id="run-skillevaluator",
                case_id=case.id,
                scanner="skillevaluator",
                scanner_version="1.0.0",
                applicable=True,
                outcome=Outcome.TIMEOUT,
                duration_ms=execution.duration_ms,
            )

        findings: List[NormalizedFinding] = []
        is_vulnerable = False

        if execution.stdout.strip():
            try:
                data = json.loads(execution.stdout)
                if not data.get("tier1_pass", True) or not data.get("tier2_dedup_pass", True):
                    is_vulnerable = True
                    findings.append(
                        NormalizedFinding(
                            scanner="skillevaluator",
                            native_rule_id="SKILLEVAL-QUALITY-DEFECT",
                            canonical_capability=case.domain,
                            severity=Severity.HIGH,
                            message="SkillEvaluator flagged quality/security defect",
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
            run_id="run-skillevaluator",
            case_id=case.id,
            scanner="skillevaluator",
            scanner_version="1.0.0",
            applicable=True,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )
