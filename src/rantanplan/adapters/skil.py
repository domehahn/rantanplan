"""
SKIL Scanner Adapter implementation.
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


class SKILAdapter(ScannerAdapter):
    """Adapter for SKIL (Skill Inspector & Linter)."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or os.environ.get("RANTANPLAN_SKIL_BIN") or shutil.which("skil") or "/Users/dominikhahn/go/bin/skil"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="skil",
            version="0.1.0",
            binary_path=self.binary_path,
        )

    def doctor(self) -> DoctorResult:
        if not os.path.exists(self.binary_path) and not shutil.which(self.binary_path):
            return DoctorResult(
                installed=False,
                version="not installed",
                path=self.binary_path,
                supported=False,
                status_message="SKIL binary not found",
            )
        return DoctorResult(
            installed=True,
            version="0.1.0",
            path=self.binary_path,
            supported=True,
            status_message="SKIL binary available and compatible",
        )

    def capabilities(self) -> List[str]:
        return [
            "secret.exfiltration",
            "prompt.injection",
            "code.execution",
            "artifact.obfuscation",
            "artifact.integrity",
            "mcp.tool-poisoning",
            "dependency.vulnerable",
            "quality.structure",
        ]

    def supports(self, case: TestCase) -> bool:
        app = case.applicability.skil
        return app != ApplicabilityState.NOT_APPLICABLE

    def build_command(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> List[str]:
        return [self.binary_path, "scan", fixture_dir, "--format", "json"]

    def run(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = self.build_command(case, profile, fixture_dir)
        runner = SandboxRunner(timeout_seconds=profile.timeout_seconds)
        return runner.execute(cmd, scanner_name="skil")

    def parse(self, case: TestCase, execution: RawExecution) -> NormalizedResult:
        if execution.timed_out:
            return NormalizedResult(
                run_id="run-skil",
                case_id=case.id,
                scanner="skil",
                scanner_version="0.1.0",
                applicable=True,
                outcome=Outcome.TIMEOUT,
                duration_ms=execution.duration_ms,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        if execution.exit_code not in (0, 1):
            return NormalizedResult(
                run_id="run-skil",
                case_id=case.id,
                scanner="skil",
                scanner_version="0.1.0",
                applicable=True,
                outcome=Outcome.ERROR,
                duration_ms=execution.duration_ms,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        findings: List[NormalizedFinding] = []
        is_vulnerable = False

        if execution.stdout.strip():
            try:
                data = json.loads(execution.stdout)
                is_vulnerable = data.get("vulnerable", False) or len(data.get("findings", [])) > 0

                for item in data.get("findings", []):
                    findings.append(
                        NormalizedFinding(
                            scanner="skil",
                            native_rule_id=item.get("rule_id", "SKIL-GENERIC"),
                            canonical_capability=case.domain,
                            severity=Severity.HIGH,
                            message=item.get("message", "Security finding detected by SKIL"),
                            native_evidence=item,
                        )
                    )
            except json.JSONDecodeError:
                if execution.exit_code == 1:
                    is_vulnerable = True

        expected_malicious = case.ground_truth.get("malicious", False)

        if is_vulnerable:
            outcome = Outcome.DETECTED if expected_malicious else Outcome.FAIL
        else:
            outcome = Outcome.NOT_DETECTED if expected_malicious else Outcome.PASS

        return NormalizedResult(
            run_id="run-skil",
            case_id=case.id,
            scanner="skil",
            scanner_version="0.1.0",
            applicable=True,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )

