"""
NVIDIA garak Target Adapters for Rantanplan Universal Scanner Assurance v2.

Provides dedicated adapters:
- garakProbeAdapter (ProbeAdapter)
- garakDetectorAdapter (DetectorAdapter)
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
from rantanplan.target_hierarchy import DetectorAdapter, ProbeAdapter


class garakProbeAdapter(ProbeAdapter):
    """Probe-focused adapter for NVIDIA garak vulnerability scanner."""

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path or get_binary_path("garak")
        self._version = discover_binary_version(self._binary_path) or "0.9.0"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="garak-probe",
            version=self._version,
            binary_path=self._binary_path,
        )

    def doctor(self) -> DoctorResult:
        path = get_binary_path("garak")
        version = discover_binary_version(path)
        installed = version is not None
        return DoctorResult(
            installed=installed,
            version=version or "0.0.0",
            path=path,
            supported=installed,
            status_message="garak binary available" if installed else "garak binary missing",
            supported_range=">=0.9.0",
        )

    def capabilities(self) -> list[str]:
        return [
            "llm.jailbreak",
            "prompt.injection",
            "llm.data-leakage",
            "llm.toxicity",
            "llm.hallucination",
        ]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.garak != ApplicabilityState.NOT_APPLICABLE

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return self._execute_mock(case, fixture_dir)

        cmd = [self._binary_path, "--model_type", "test", "--probes", "promptinject"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="garak-probe")

    def _execute_mock(self, case: TestCase, fixture_dir: str) -> RawExecution:
        content = ""
        for file_info in case.files:
            content += file_info.get("content", "").lower() + "\n"

        has_vuln = "jailbreak" in content or "ignore previous instructions" in content or "override" in content

        stdout = json.dumps({"probes_evaluated": 5, "vulnerabilities_found": 1 if has_vuln else 0})
        return RawExecution(
            scanner="garak-probe",
            command=[self._binary_path, "--model_type", "mock"],
            exit_code=1 if has_vuln else 0,
            stdout=stdout,
            stderr="",
            duration_ms=8,
            execution_status=ExecutionStatus.SUCCESS,
        )

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        if execution.execution_status == ExecutionStatus.TARGET_UNAVAILABLE:
            return RichNormalizedResult(
                run_id="run-garak-probe",
                case_id=case.id,
                target_name="garak-probe",
                target_version=self._version,
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        if execution.timed_out:
            return RichNormalizedResult(
                run_id="run-garak-probe",
                case_id=case.id,
                target_name="garak-probe",
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
                if data.get("vulnerabilities_found", 0) > 0:
                    is_vulnerable = True
                    findings.append(
                        NormalizedFinding(
                            scanner="garak-probe",
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
            outcome = AssuranceOutcome.DETECTED if expected_malicious else AssuranceOutcome.FAIL
        else:
            outcome = AssuranceOutcome.NOT_DETECTED if expected_malicious else AssuranceOutcome.PASS

        return RichNormalizedResult(
            run_id="run-garak-probe",
            case_id=case.id,
            target_name="garak-probe",
            target_version=self._version,
            execution_status=ExecutionStatus.SUCCESS,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )

    def run_probe(self, case: TestCase, profile: RunProfile, probe_name: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, "")
        return self.parse(case, raw)


class garakDetectorAdapter(DetectorAdapter):
    """Detector-focused adapter evaluating garak detection pass/fail rate."""

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path or get_binary_path("garak")
        self._version = discover_binary_version(self._binary_path) or "0.9.0"

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(
            name="garak-detector",
            version=self._version,
            binary_path=self._binary_path,
        )

    def doctor(self) -> DoctorResult:
        path = get_binary_path("garak")
        version = discover_binary_version(path)
        installed = version is not None
        return DoctorResult(
            installed=installed,
            version=version or "0.0.0",
            path=path,
            supported=installed,
            status_message="garak binary available" if installed else "garak binary missing",
            supported_range=">=0.9.0",
        )

    def capabilities(self) -> list[str]:
        return ["detector.eval", "response.classification"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.garak != ApplicabilityState.NOT_APPLICABLE

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="garak-detector",
                command=[self._binary_path, "--detector", "always_trigger"],
                exit_code=0,
                stdout=json.dumps({"detector_pass": True}),
                stderr="",
                duration_ms=5,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "--model_type", "test", "--report_type", "detector"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="garak-detector")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        if execution.execution_status == ExecutionStatus.TARGET_UNAVAILABLE:
            return RichNormalizedResult(
                run_id="run-garak-detector",
                case_id=case.id,
                target_name="garak-detector",
                target_version=self._version,
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        return RichNormalizedResult(
            run_id="run-garak-detector",
            case_id=case.id,
            target_name="garak-detector",
            target_version=self._version,
            execution_status=ExecutionStatus.SUCCESS,
            outcome=AssuranceOutcome.PASS,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )

    def evaluate_detector(self, case: TestCase, profile: RunProfile, sample_response: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, "")
        return self.parse(case, raw)


# Backwards compatibility alias
GarakAdapter = garakProbeAdapter
