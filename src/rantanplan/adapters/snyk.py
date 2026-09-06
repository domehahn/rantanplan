"""
Snyk Agent Scan Adapter implementation for Rantanplan Universal Scanner Assurance v2.
"""

import json

from rantanplan.execution import ExecutionSandbox, discover_binary_version, get_binary_path
from rantanplan.models import (
    ApplicabilityState,
    AssuranceOutcome,
    DoctorResult,
    ExecutionStatus,
    NormalizedFinding,
    RawExecution,
    RichNormalizedResult,
    RunProfile,
    ScannerIdentity,
    Severity,
    TargetProfile,
    TestCase,
)
from rantanplan.target_hierarchy import ArtifactScannerAdapter


class SnykAgentScanAdapter(ArtifactScannerAdapter):
    """Production adapter for Snyk Agent Scan (Snyk CLI)."""

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path or get_binary_path("snyk")
        self._version = discover_binary_version(self._binary_path) or "1.1200.0"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="snyk-agent",
            version=self._version,
            binary_path=self._binary_path,
        )

    def doctor(self) -> DoctorResult:
        path = get_binary_path("snyk")
        version = discover_binary_version(path)
        installed = version is not None
        return DoctorResult(
            installed=installed,
            version=version or "0.0.0",
            path=path,
            supported=installed,
            status_message="Snyk CLI available" if installed else "Snyk CLI not installed",
            supported_range=">=1.1000.0",
        )

    def capabilities(self) -> list[str]:
        return [
            "dependency.vulnerable",
            "license.compliance",
            "container.vulnerability",
            "agent.misconfiguration",
        ]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.snyk != ApplicabilityState.NOT_APPLICABLE

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return self._execute_mock(case, fixture_dir)

        cmd = [self._binary_path, "code", "test", fixture_dir, "--json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="snyk-agent")

    def _execute_mock(self, case: TestCase, fixture_dir: str) -> RawExecution:
        content = ""
        for file_info in case.files:
            content += file_info.get("content", "").lower() + "\n"

        has_vuln = "vulnerable" in content or "cve-" in content

        stdout = json.dumps({"vulnerabilities": [{"id": "SNYK-PYTHON-VULN-1", "title": "Vulnerable dependency"}] if has_vuln else []})
        return RawExecution(
            scanner="snyk-agent",
            command=[self._binary_path, "code", "test", fixture_dir],
            exit_code=1 if has_vuln else 0,
            stdout=stdout,
            stderr="",
            duration_ms=8,
            execution_status=ExecutionStatus.SUCCESS,
        )

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        if execution.execution_status == ExecutionStatus.TARGET_UNAVAILABLE:
            return RichNormalizedResult(
                run_id="run-snyk-agent",
                case_id=case.id,
                target_name="snyk-agent",
                target_version=self._version,
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        if execution.timed_out:
            return RichNormalizedResult(
                run_id="run-snyk-agent",
                case_id=case.id,
                target_name="snyk-agent",
                target_version=self._version,
                execution_status=ExecutionStatus.TIMEOUT,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        findings: list[NormalizedFinding] = []
        is_vulnerable = False

        if execution.stdout.strip():
            try:
                data = json.loads(execution.stdout)
                vulns = data.get("vulnerabilities", []) or data.get("runs", [])
                if vulns:
                    is_vulnerable = True
                    for vuln in vulns:
                        findings.append(
                            NormalizedFinding(
                                scanner="snyk-agent",
                                native_rule_id=vuln.get("id", "SNYK-VULN"),
                                canonical_capability=case.domain,
                                severity=Severity.HIGH,
                                message=vuln.get("title", "Snyk vulnerability finding"),
                                native_evidence=vuln,
                            )
                        )
            except json.JSONDecodeError:
                if execution.exit_code != 0:
                    is_vulnerable = True

        expected_malicious = case.ground_truth.get("malicious", False)

        if is_vulnerable:
            outcome = AssuranceOutcome.DETECTED if expected_malicious else AssuranceOutcome.FAIL
        else:
            outcome = AssuranceOutcome.NOT_DETECTED if expected_malicious else AssuranceOutcome.PASS

        return RichNormalizedResult(
            run_id="run-snyk-agent",
            case_id=case.id,
            target_name="snyk-agent",
            target_version=self._version,
            execution_status=ExecutionStatus.SUCCESS,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)
