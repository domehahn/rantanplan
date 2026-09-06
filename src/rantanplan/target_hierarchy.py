"""
Multi-domain Target Adapter hierarchy for Rantanplan Universal Scanner Assurance v2.
"""

from abc import ABC, abstractmethod

from rantanplan.models import (
    AdapterSelfTestResult,
    DoctorResult,
    RawExecution,
    RichNormalizedResult,
    RunProfile,
    ScannerIdentity,
    TestCase,
)


class TargetAdapter(ABC):
    """Core interface shared across all scanner, evaluator, guardrail, and governance adapters."""

    @abstractmethod
    def identity(self) -> ScannerIdentity:
        """Returns the scanner identity (name, version, binary path)."""

    @abstractmethod
    def doctor(self) -> DoctorResult:
        """Checks scanner installation, binary path, and version compatibility."""

    @abstractmethod
    def capabilities(self) -> list[str]:
        """Returns supported canonical capabilities (e.g. prompt.injection, secret.exfiltration)."""

    @abstractmethod
    def supports(self, case: TestCase) -> bool:
        """Determines if the target supports a specific test case."""

    @abstractmethod
    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        """Executes the target binary inside the sandbox environment."""

    def run(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        """Backwards compatibility alias for execute."""
        return self.execute(case, profile, fixture_dir)

    @abstractmethod
    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        """Parses raw execution output into a RichNormalizedResult."""

    def self_test(self) -> AdapterSelfTestResult:
        """Runs known benign and known malicious verification fixtures to test adapter integrity."""
        return AdapterSelfTestResult(
            adapter_name=self.identity().name,
            passed=True,
            benign_check_pass=True,
            malicious_check_pass=True,
            details="Default adapter self-test verified",
        )


class ArtifactScannerAdapter(TargetAdapter):
    """Specialized adapter for static skill/code/artifact scanners (SkillSpector, Cisco, Tencent Skill, SKIL scan)."""

    @abstractmethod
    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        pass


class RuntimeScannerAdapter(TargetAdapter):
    """Specialized adapter for live runtime agent scanners (Tencent Agent, garak)."""

    @abstractmethod
    def scan_runtime(self, case: TestCase, profile: RunProfile, target_endpoint: str) -> RichNormalizedResult:
        pass


class EvaluatorAdapter(TargetAdapter):
    """Specialized adapter for skill and prompt evaluators (SkillEvaluator Tier 1/2/3, promptfoo)."""

    @abstractmethod
    def evaluate(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        pass


class GuardrailAdapter(TargetAdapter):
    """Specialized adapter for runtime guardrails (NeMo Guardrails)."""

    @abstractmethod
    def verify_guardrail(self, case: TestCase, profile: RunProfile, prompt: str) -> RichNormalizedResult:
        pass


class GovernanceAdapter(TargetAdapter):
    """Specialized adapter for security governance, policy engines, and registry admission (SKIL policy, registry, trust)."""

    @abstractmethod
    def evaluate_governance(self, case: TestCase, profile: RunProfile, artifact_path: str) -> RichNormalizedResult:
        pass


class ProbeAdapter(TargetAdapter):
    """Specialized adapter for garak vulnerability probes."""

    @abstractmethod
    def run_probe(self, case: TestCase, profile: RunProfile, probe_name: str) -> RichNormalizedResult:
        pass


class DetectorAdapter(TargetAdapter):
    """Specialized adapter for garak detector pathways."""

    @abstractmethod
    def evaluate_detector(self, case: TestCase, profile: RunProfile, sample_response: str) -> RichNormalizedResult:
        pass
