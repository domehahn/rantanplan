"""
SKIL Sub-Adapter Suite for Rantanplan Universal Scanner Assurance v2.

Provides dedicated adapters for all SKIL subcommands:
- SKILStaticScanAdapter (ArtifactScannerAdapter)
- SKILSemanticScanAdapter (ArtifactScannerAdapter)
- SKILValidateAdapter (ArtifactScannerAdapter)
- SKILLintAdapter (ArtifactScannerAdapter)
- SKILVerifyAdapter (EvaluatorAdapter)
- SKILEvalAdapter (EvaluatorAdapter)
- SKILRegistryAdmissionAdapter (GovernanceAdapter)
- SKILPolicyAdapter (GovernanceAdapter)
- SKILTrustAdapter (GovernanceAdapter)
- SKILProvenanceAdapter (GovernanceAdapter)
- SKILAttestationAdapter (GovernanceAdapter)
- SKILRuntimePolicyAdapter (GovernanceAdapter)
"""

import json

from rantanplan.execution import ExecutionSandbox, discover_binary_version, get_binary_path
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
from rantanplan.target_hierarchy import ArtifactScannerAdapter, EvaluatorAdapter, GovernanceAdapter


class BaseSKILAdapter:
    """Base helper for SKIL family adapters."""

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path or get_binary_path("skil")
        self._version = discover_binary_version(self._binary_path) or "0.1.0"

    def doctor(self) -> DoctorResult:
        path = get_binary_path("skil")
        version = discover_binary_version(path)
        installed = version is not None
        return DoctorResult(
            installed=installed,
            version=version or "0.0.0",
            path=path,
            supported=installed,
            status_message="SKIL binary available" if installed else "SKIL binary missing",
            supported_range=">=0.1.0",
        )

    def _parse_common(self, case: TestCase, execution: RawExecution, target_subname: str) -> RichNormalizedResult:
        if execution.execution_status == ExecutionStatus.TARGET_UNAVAILABLE:
            return RichNormalizedResult(
                run_id=f"run-{target_subname}",
                case_id=case.id,
                target_name=target_subname,
                target_version=self._version,
                execution_status=ExecutionStatus.TARGET_UNAVAILABLE,
                outcome=AssuranceOutcome.INCOMPLETE,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                raw_report=execution.stdout + "\n" + execution.stderr,
            )

        if execution.timed_out:
            return RichNormalizedResult(
                run_id=f"run-{target_subname}",
                case_id=case.id,
                target_name=target_subname,
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
                is_vulnerable = data.get("vulnerable", False) or len(data.get("findings", [])) > 0
                for item in data.get("findings", []):
                    findings.append(
                        NormalizedFinding(
                            scanner=target_subname,
                            native_rule_id=item.get("rule_id", "SKIL-GENERIC"),
                            canonical_capability=case.domain,
                            severity=Severity.HIGH,
                            message=item.get("message", f"Security finding detected by {target_subname}"),
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
            run_id=f"run-{target_subname}",
            case_id=case.id,
            target_name=target_subname,
            target_version=self._version,
            execution_status=ExecutionStatus.SUCCESS,
            outcome=outcome,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )


class SKILStaticScanAdapter(BaseSKILAdapter, ArtifactScannerAdapter):
    """SKIL static code & AST scanner."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-static", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["secret.exfiltration", "command.injection", "path.traversal", "prompt.injection"]

    def supports(self, case: TestCase) -> bool:
        return case.kind == "artifact"

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "scan", "--mode", "static", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-static")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-static")

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class SKILSemanticScanAdapter(BaseSKILAdapter, ArtifactScannerAdapter):
    """SKIL semantic LLM-driven skill scanner."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-semantic", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["prompt.injection", "jailbreak", "social.engineering", "logic.bypass"]

    def supports(self, case: TestCase) -> bool:
        return case.kind == "artifact"

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "scan", "--mode", "semantic", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-semantic")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-semantic")

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class SKILValidateAdapter(BaseSKILAdapter, ArtifactScannerAdapter):
    """SKIL skill structure & manifest validation."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-validate", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["manifest.validation", "format.integrity"]

    def supports(self, case: TestCase) -> bool:
        return case.kind == "artifact"

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "validate", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-validate")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-validate")

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class SKILLintAdapter(BaseSKILAdapter, ArtifactScannerAdapter):
    """SKIL skill style, security linting & anti-pattern checker."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-lint", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["code.lint", "security.best_practices"]

    def supports(self, case: TestCase) -> bool:
        return case.kind == "artifact"

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "lint", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-lint")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-lint")

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class SKILVerifyAdapter(BaseSKILAdapter, EvaluatorAdapter):
    """SKIL skill correctness & safety verification."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-verify", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["correctness.verification", "safety.verification"]

    def supports(self, case: TestCase) -> bool:
        return case.kind in ("artifact", "runtime")

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "verify", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-verify")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-verify")

    def evaluate(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class SKILEvalAdapter(BaseSKILAdapter, EvaluatorAdapter):
    """SKIL quantitative evaluation benchmark."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-eval", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["quantitative.evaluation", "benchmark.score"]

    def supports(self, case: TestCase) -> bool:
        return case.kind in ("artifact", "runtime")

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "eval", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-eval")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-eval")

    def evaluate(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class SKILRegistryAdmissionAdapter(BaseSKILAdapter, GovernanceAdapter):
    """SKIL registry admission policy gate."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-registry", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["registry.admission", "policy.gate"]

    def supports(self, case: TestCase) -> bool:
        return case.kind in ("artifact", "catalog")

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "registry", "check", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-registry")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-registry")

    def evaluate_governance(self, case: TestCase, profile: RunProfile, artifact_path: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, artifact_path)
        return self.parse(case, raw)


class SKILPolicyAdapter(BaseSKILAdapter, GovernanceAdapter):
    """SKIL OPA/rego security policy engine."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-policy", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["policy.compliance", "governance.enforcement"]

    def supports(self, case: TestCase) -> bool:
        return True

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "policy", "verify", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-policy")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-policy")

    def evaluate_governance(self, case: TestCase, profile: RunProfile, artifact_path: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, artifact_path)
        return self.parse(case, raw)


class SKILTrustAdapter(BaseSKILAdapter, GovernanceAdapter):
    """SKIL publisher trust & reputation evaluation."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-trust", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["publisher.trust", "identity.verification"]

    def supports(self, case: TestCase) -> bool:
        return True

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "trust", "check", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-trust")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-trust")

    def evaluate_governance(self, case: TestCase, profile: RunProfile, artifact_path: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, artifact_path)
        return self.parse(case, raw)


class SKILProvenanceAdapter(BaseSKILAdapter, GovernanceAdapter):
    """SKIL artifact supply chain & provenance verification."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-provenance", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["supply_chain.provenance", "signature.verification"]

    def supports(self, case: TestCase) -> bool:
        return True

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "provenance", "verify", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-provenance")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-provenance")

    def evaluate_governance(self, case: TestCase, profile: RunProfile, artifact_path: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, artifact_path)
        return self.parse(case, raw)


class SKILAttestationAdapter(BaseSKILAdapter, GovernanceAdapter):
    """SKIL cryptographic attestation validator."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-attestation", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["attestation.verification", "cryptographic.claim"]

    def supports(self, case: TestCase) -> bool:
        return True

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "attestation", "verify", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-attestation")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-attestation")

    def evaluate_governance(self, case: TestCase, profile: RunProfile, artifact_path: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, artifact_path)
        return self.parse(case, raw)


class SKILRuntimePolicyAdapter(BaseSKILAdapter, GovernanceAdapter):
    """SKIL runtime policy enforcement validator."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="skil-runtime-policy", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["runtime.policy", "execution.guard"]

    def supports(self, case: TestCase) -> bool:
        return True

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        cmd = [self._binary_path, "runtime-policy", "verify", fixture_dir]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="skil-runtime-policy")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "skil-runtime-policy")

    def evaluate_governance(self, case: TestCase, profile: RunProfile, artifact_path: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, artifact_path)
        return self.parse(case, raw)
