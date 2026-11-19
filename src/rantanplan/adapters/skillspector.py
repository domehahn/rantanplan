"""
NVIDIA SkillSpector Target Adapter implementation for Rantanplan Universal Scanner Assurance v2.
"""

import json

from rantanplan.adapters._common import incomplete_result, unusable_report
from rantanplan.execution import (
    ExecutionSandbox,
    binary_exists,
    discover_binary_version,
    get_binary_path,
)
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


class SkillSpectorAdapter(ArtifactScannerAdapter):
    """Production adapter for NVIDIA SkillSpector."""

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path or get_binary_path("skillspector")
        self._version = discover_binary_version(self._binary_path) or "1.2.0"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="skillspector",
            version=self._version,
            binary_path=self._binary_path,
        )

    def doctor(self) -> DoctorResult:
        path = get_binary_path("skillspector")
        version = discover_binary_version(path)
        installed = binary_exists(path)
        return DoctorResult(
            installed=installed,
            version=version or "0.0.0",
            path=path,
            supported=installed,
            status_message="SkillSpector binary available" if installed else "SkillSpector binary not installed",
            supported_range=">=1.0.0",
        )

    def capabilities(self) -> list[str]:
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

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return self._execute_mock(case, fixture_dir)

        cmd = [self._binary_path, "inspect", "--path", fixture_dir, "--json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skillspector")

    def _execute_mock(self, case: TestCase, fixture_dir: str) -> RawExecution:
        content = ""
        for file_info in case.files:
            content += file_info.get("content", "").lower() + "\n"

        has_vuln = ("secret" in content and "send" in content) or "attacker.example.com" in content or "ignore previous instructions" in content

        stdout = json.dumps({"issues": [{"code": "SKILLSPECTOR-VULN", "title": "Detected vulnerability"}]}) if has_vuln else json.dumps({"issues": []})
        return RawExecution(
            scanner="skillspector",
            command=[self._binary_path, "inspect", fixture_dir],
            exit_code=1 if has_vuln else 0,
            stdout=stdout,
            stderr="",
            duration_ms=5,
            execution_status=ExecutionStatus.SUCCESS,
        )

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        if execution.execution_status == ExecutionStatus.TARGET_UNAVAILABLE:
            return RichNormalizedResult(
                run_id="run-skillspector",
                case_id=case.id,
                target_name="skillspector",
                target_version=self._version,
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        if execution.timed_out:
            return RichNormalizedResult(
                run_id="run-skillspector",
                case_id=case.id,
                target_name="skillspector",
                target_version=self._version,
                execution_status=ExecutionStatus.TIMEOUT,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        findings: list[NormalizedFinding] = []
        is_vulnerable = False

        unusable = unusable_report(case, execution, self.identity().name, self._version)
        if unusable is not None:
            return unusable

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
                return incomplete_result(
                    case, execution, self.identity().name, self._version,
                    ExecutionStatus.PARSER_ERROR, "stdout is not valid JSON",
                )

        expected_malicious = case.ground_truth.get("malicious", False)

        if is_vulnerable:
            outcome = AssuranceOutcome.DETECTED if expected_malicious else AssuranceOutcome.FAIL
        else:
            outcome = AssuranceOutcome.NOT_DETECTED if expected_malicious else AssuranceOutcome.PASS

        return RichNormalizedResult(
            run_id="run-skillspector",
            case_id=case.id,
            target_name="skillspector",
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
