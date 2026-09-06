"""
Declarative Universal Adapter SDK for loading third-party scanner YAML manifests.
"""

import json
import os
import shutil
from typing import Any

import yaml

from rantanplan.execution import SandboxRunner, discover_binary_version, resolve_binary_path
from rantanplan.models import (
    AssuranceOutcome,
    DoctorResult,
    ExecutionStatus,
    NormalizedFinding,
    RawExecution,
    RichNormalizedResult,
    RunProfile,
    ScannerIdentity,
    Severity,
    TestCase,
)
from rantanplan.target_hierarchy import TargetAdapter


class ManifestScannerAdapter(TargetAdapter):
    """Adapter constructed dynamically from a declarative YAML target manifest."""

    def __init__(self, manifest_data: dict[str, Any], binary_override: str | None = None):
        self.manifest = manifest_data
        self.name = manifest_data.get("name", "custom-scanner")
        self.binary_name = manifest_data.get("binary", {}).get("command", self.name)
        self.binary_path = resolve_binary_path(self.binary_name, binary_override)

    def identity(self) -> ScannerIdentity:
        ver = discover_binary_version(self.binary_path)
        return ScannerIdentity(
            name=self.name,
            version=ver,
            binary_path=self.binary_path,
        )

    def doctor(self) -> DoctorResult:
        path_exists = shutil.which(self.binary_path) is not None or os.path.exists(self.binary_path)
        ver = discover_binary_version(self.binary_path) if path_exists else "VERSION_UNKNOWN"
        return DoctorResult(
            installed=path_exists,
            version=ver,
            path=self.binary_path,
            supported=path_exists,
            status_message=f"Manifest scanner {self.name} available" if path_exists else f"Binary {self.binary_name} not found",
        )

    def capabilities(self) -> list[str]:
        return self.manifest.get("capabilities", [])

    def supports(self, case: TestCase) -> bool:
        return case.domain in self.capabilities()

    def build_command(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> list[str]:
        scan_template = self.manifest.get("scan", {}).get("command", [self.binary_name, "scan", "{{fixture}}"])
        return [arg.replace("{{fixture}}", fixture_dir) for arg in scan_template]

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if not (shutil.which(self.binary_path) or os.path.exists(self.binary_path)):
            return RawExecution(
                scanner=self.name,
                command=[],
                exit_code=-1,
                stdout="",
                stderr=f"Binary {self.binary_path} not installed",
                duration_ms=0,
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
            )

        cmd = self.build_command(case, profile, fixture_dir)
        runner = SandboxRunner(timeout_seconds=profile.timeout_seconds)
        return runner.execute(cmd, scanner_name=self.name)

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        if execution.execution_status == ExecutionStatus.TARGET_UNAVAILABLE:
            return RichNormalizedResult(
                run_id=f"run-{self.name}",
                case_id=case.id,
                target_name=self.name,
                target_version="VERSION_UNKNOWN",
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
                outcome=AssuranceOutcome.NOT_APPLICABLE,
                duration_ms=0,
            )

        if execution.timed_out:
            return RichNormalizedResult(
                run_id=f"run-{self.name}",
                case_id=case.id,
                target_name=self.name,
                target_version="1.0.0",
                execution_status=ExecutionStatus.TIMEOUT,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
            )

        findings: list[NormalizedFinding] = []
        is_vulnerable = False

        finding_exits = self.manifest.get("exit_codes", {}).get("finding", [1])
        if execution.exit_code in finding_exits:
            is_vulnerable = True

        if execution.stdout.strip():
            try:
                data = json.loads(execution.stdout)
                if isinstance(data, dict) and data.get("findings"):
                    is_vulnerable = True
                    for item in data["findings"]:
                        findings.append(
                            NormalizedFinding(
                                scanner=self.name,
                                native_rule_id=item.get("rule_id", "MANIFEST-RULE"),
                                canonical_capability=case.domain,
                                severity=Severity.HIGH,
                                message=item.get("message", "Manifest scanner finding"),
                                native_evidence=item,
                            )
                        )
            except json.JSONDecodeError:
                pass

        expected_malicious = case.ground_truth.get("malicious", False)
        if is_vulnerable:
            outcome = AssuranceOutcome.DETECTED if expected_malicious else AssuranceOutcome.FAIL
        else:
            outcome = AssuranceOutcome.NOT_DETECTED if expected_malicious else AssuranceOutcome.PASS

        return RichNormalizedResult(
            run_id=f"run-{self.name}",
            case_id=case.id,
            target_name=self.name,
            target_version="1.0.0",
            execution_status=execution.execution_status,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )


def load_manifest_adapter(manifest_path: str) -> ManifestScannerAdapter:
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ManifestScannerAdapter(data)
