"""
Promptfoo Adapter Suite for Rantanplan Universal Scanner Assurance v2.

Provides dedicated adapters:
- PromptfooEvalAdapter (EvaluatorAdapter)
- PromptfooAssertionAdapter (EvaluatorAdapter)
- PromptfooRedTeamAdapter (ProbeAdapter)
- PromptfooJudgeAdapter (EvaluatorAdapter)
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
from rantanplan.target_hierarchy import EvaluatorAdapter, ProbeAdapter


class BasePromptfooAdapter:
    """Base helper for promptfoo adapters."""

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path or get_binary_path("promptfoo")
        self._version = discover_binary_version(self._binary_path) or "0.90.0"

    def doctor(self) -> DoctorResult:
        path = get_binary_path("promptfoo")
        version = discover_binary_version(path)
        installed = version is not None
        return DoctorResult(
            installed=installed,
            version=version or "0.0.0",
            path=path,
            supported=installed,
            status_message="promptfoo CLI available" if installed else "promptfoo CLI not installed",
            supported_range=">=0.80.0",
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
                summary = data.get("summary", {})
                if summary.get("failed", 0) > 0:
                    is_vulnerable = True
                    findings.append(
                        NormalizedFinding(
                            scanner=subname,
                            native_rule_id="PROMPTFOO-FAIL",
                            canonical_capability=case.domain,
                            severity=Severity.HIGH,
                            message="promptfoo assertion or redteam probe failed",
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


class PromptfooEvalAdapter(BasePromptfooAdapter, EvaluatorAdapter):
    """Promptfoo prompt & model evaluation adapter."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="promptfoo-eval", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["prompt.evaluation", "assertion.verification"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.promptfoo != ApplicabilityState.NOT_APPLICABLE

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="promptfoo-eval",
                command=[self._binary_path, "eval"],
                exit_code=0,
                stdout=json.dumps({"summary": {"passed": 1, "failed": 0}}),
                stderr="",
                duration_ms=5,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "eval", "--no-progress-bar", "--output", "json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="promptfoo-eval")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "promptfoo-eval")

    def evaluate(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class PromptfooAssertionAdapter(BasePromptfooAdapter, EvaluatorAdapter):
    """Promptfoo assertion engine adapter."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="promptfoo-assertion", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["assertion.check", "output.validation"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.promptfoo != ApplicabilityState.NOT_APPLICABLE

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="promptfoo-assertion",
                command=[self._binary_path, "eval"],
                exit_code=0,
                stdout=json.dumps({"summary": {"passed": 1, "failed": 0}}),
                stderr="",
                duration_ms=5,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "eval", "--assertions-only", "--output", "json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="promptfoo-assertion")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "promptfoo-assertion")

    def evaluate(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class PromptfooRedTeamAdapter(BasePromptfooAdapter, ProbeAdapter):
    """Promptfoo red teaming module adapter."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="promptfoo-redteam", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["redteam.probe", "jailbreak.generation"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.promptfoo != ApplicabilityState.NOT_APPLICABLE

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="promptfoo-redteam",
                command=[self._binary_path, "redteam", "run"],
                exit_code=0,
                stdout=json.dumps({"summary": {"passed": 1, "failed": 0}}),
                stderr="",
                duration_ms=5,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "redteam", "run", "--output", "json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="promptfoo-redteam")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "promptfoo-redteam")

    def run_probe(self, case: TestCase, profile: RunProfile, probe_name: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, "")
        return self.parse(case, raw)


class PromptfooJudgeAdapter(BasePromptfooAdapter, EvaluatorAdapter):
    """Promptfoo LLM-as-a-judge adapter."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="promptfoo-judge", version=self._version, binary_path=self._binary_path)

    def capabilities(self) -> list[str]:
        return ["llm_judge.eval", "model.grading"]

    def supports(self, case: TestCase) -> bool:
        return case.applicability.promptfoo != ApplicabilityState.NOT_APPLICABLE

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        if profile.profile_type == TargetProfile.MOCK:
            return RawExecution(
                scanner="promptfoo-judge",
                command=[self._binary_path, "eval"],
                exit_code=0,
                stdout=json.dumps({"summary": {"passed": 1, "failed": 0}}),
                stderr="",
                duration_ms=5,
                execution_status=ExecutionStatus.SUCCESS,
            )

        cmd = [self._binary_path, "eval", "--judge-only", "--output", "json"]
        return ExecutionSandbox.run_command(cmd, timeout=profile.timeout_seconds, target_name="promptfoo-judge")

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        return self._parse_common(case, execution, "promptfoo-judge")

    def evaluate(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)
