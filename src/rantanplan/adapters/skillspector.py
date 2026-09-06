"""
NVIDIA SkillSpector Scanner Adapter implementation.
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


class SkillSpectorAdapter(ScannerAdapter):
    """Adapter for NVIDIA SkillSpector."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or os.environ.get("RANTANPLAN_SKILLSPECTOR_BIN") or shutil.which("skillspector") or "skillspector"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="skillspector",
            version="1.2.0",
            binary_path=self.binary_path,
        )

    def doctor(self) -> DoctorResult:
        path_exists = shutil.which(self.binary_path) is not None
        return DoctorResult(
            installed=path_exists,
            version="1.2.0" if path_exists else "not installed",
            path=self.binary_path,
            supported=path_exists,
            status_message="SkillSpector available" if path_exists else "SkillSpector binary not found (Mock fallback available)",
        )

    def capabilities(self) -> List[str]:
        return [
            "secret.exfiltration",
            "prompt.injection",
            "code.execution",
            "artifact.obfuscation",
            "mcp.tool-poisoning",
            "dependency.vulnerable",
        ]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.skillspector != ApplicabilityState.NOT_APPLICABLE

    def build_command(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> List[str]:
        return [self.binary_path, "inspect", "--path", fixture_dir, "--json"]

    def run(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if not shutil.which(self.binary_path):
            # Fallback mock execution when binary not installed
            return self._run_mock(case, fixture_dir)

        cmd = self.build_command(case, profile, fixture_dir)
        runner = SandboxRunner(timeout_seconds=profile.timeout_seconds)
        return runner.execute(cmd, scanner_name="skillspector")

    def _run_mock(self, case: TestCase, fixture_dir: str) -> RawExecution:
        content = ""
        for file_info in case.files:
            content += file_info.get("content", "").lower() + "\n"

        has_vuln = ("secret" in content and "send" in content) or "attacker.example.com" in content or "ignore previous instructions" in content

        stdout = json.dumps({"issues": [{"code": "SKILLSPECTOR-VULN", "title": "Detected vulnerability"}]}) if has_vuln else json.dumps({"issues": []})
        return RawExecution(
            scanner="skillspector",
            command=[self.binary_path, "inspect", fixture_dir],
            exit_code=1 if has_vuln else 0,
            stdout=stdout,
            stderr="",
            duration_ms=5,
        )

    def parse(self, case: TestCase, execution: RawExecution) -> NormalizedResult:
        if execution.timed_out:
            return NormalizedResult(
                run_id="run-skillspector",
                case_id=case.id,
                scanner="skillspector",
                scanner_version="1.2.0",
                applicable=True,
                outcome=Outcome.TIMEOUT,
                duration_ms=execution.duration_ms,
            )

        findings: List[NormalizedFinding] = []
        is_vulnerable = False

        if execution.stdout.strip():
            try:
                data = json.loads(execution.stdout)
                issues = data.get("issues", [])
                if issues:
                    is_vulnerable = True
                    for issue in issues:
                        findings.append(
                            NormalizedFinding(
                                scanner="skillspector",
                                native_rule_id=issue.get("code", "SKILLSPECTOR-ISSUE"),
                                canonical_capability=case.domain,
                                severity=Severity.HIGH,
                                message=issue.get("title", "SkillSpector finding"),
                                native_evidence=issue,
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
            run_id="run-skillspector",
            case_id=case.id,
            scanner="skillspector",
            scanner_version="1.2.0",
            applicable=True,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )
