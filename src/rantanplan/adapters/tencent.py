"""
Tencent AI-Infra-Guard Adapter Suite for Rantanplan Universal Scanner Assurance v2.

Provides dedicated adapters:
- TencentSkillScannerAdapter (ArtifactScannerAdapter)
- TencentMCPScannerAdapter (ArtifactScannerAdapter)
- TencentAgentScannerAdapter (RuntimeScannerAdapter)
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
from rantanplan.target_hierarchy import ArtifactScannerAdapter, RuntimeScannerAdapter


class BaseTencentAdapter:
    """Base helper for Tencent AI-Infra-Guard adapters."""

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path or get_binary_path("tencent-ai-infra-guard")
        self._version = discover_binary_version(self._binary_path) or "1.0.0"

    def doctor(self) -> DoctorResult:
        path = get_binary_path("tencent-ai-infra-guard")
        version = discover_binary_version(path)
        installed = version is not None
        return DoctorResult(
            installed=installed,
            version=version or "0.0.0",
            path=path,
            supported=installed,
            status_message="Tencent AI-Infra-Guard binary available" if installed else "Tencent AI-Infra-Guard binary missing",
            supported_range=">=1.0.0",
        )

    def _parse_common(self, case: TestCase, execution: RawExecution, subname: str) -> RichNormalizedResult:
        if execution.execution_status == ExecutionStatus.TARGET_UNAVAILABLE:
            return RichNormalizedResult(
                run_id=f"run-{subname}",
                case_id=case.id,
                target_name=subname,
                target_version=self._version,
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        if execution.timed_out:
            return RichNormalizedResult(
                run_id=f"run-{subname}",
                case_id=case.id,
                target_name=subname,
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
                if data.get("vulnerabilities", []):
                    is_vulnerable = True
                    for item in data.get("vulnerabilities", []):
                        findings.append(
                            NormalizedFinding(
                                scanner=subname,
                                native_rule_id=item.get("rule_id", "TENCENT-GUARD"),
                                canonical_capability=case.domain,
                                severity=Severity.HIGH,
                                message=item.get("description", "Tencent AI-Infra-Guard defect detected"),
                                native_evidence=item,
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
            run_id=f"run-{subname}",
            case_id=case.id,
            target_name=subname,
            target_version=self._version,
            execution_status=ExecutionStatus.SUCCESS,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )


class TencentSkillScannerAdapter(BaseTencentAdapter, ArtifactScannerAdapter):
    """Tencent Skill Scanner adapter."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="tencent-skill", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["secret.exfiltration", "code.execution", "artifact.obfuscation"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.tencent != ApplicabilityState.NOT_APPLICABLE and case.kind == "artifact"

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="tencent-skill",
                command=[self._binary_path, "scan-skill"],
                exit_code=0,
                stdout=json.dumps({"vulnerabilities": []}),
                stderr="",
                duration_ms=6,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "scan-skill", "--path", fixture_dir, "--json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="tencent-skill")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "tencent-skill")

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class TencentMCPScannerAdapter(BaseTencentAdapter, ArtifactScannerAdapter):
    """Tencent Model Context Protocol (MCP) Scanner adapter."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="tencent-mcp", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["mcp.tool-poisoning", "mcp.schema-confusion"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.tencent != ApplicabilityState.NOT_APPLICABLE and case.kind == "artifact"

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="tencent-mcp",
                command=[self._binary_path, "scan-mcp"],
                exit_code=0,
                stdout=json.dumps({"vulnerabilities": []}),
                stderr="",
                duration_ms=6,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "scan-mcp", "--path", fixture_dir, "--json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="tencent-mcp")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "tencent-mcp")

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class TencentAgentScannerAdapter(BaseTencentAdapter, RuntimeScannerAdapter):
    """Tencent Runtime Agent Scanner adapter."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="tencent-agent", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["runtime.agent-hijack", "memory.poisoning"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.tencent != ApplicabilityState.NOT_APPLICABLE and case.kind == "runtime"

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="tencent-agent",
                command=[self._binary_path, "scan-agent"],
                exit_code=0,
                stdout=json.dumps({"vulnerabilities": []}),
                stderr="",
                duration_ms=6,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "scan-agent", "--target", fixture_dir, "--json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="tencent-agent")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "tencent-agent")

    def scan_runtime(self, case: TestCase, profile: RunProfile, target_endpoint: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, target_endpoint)
        return self.parse(case, raw)
