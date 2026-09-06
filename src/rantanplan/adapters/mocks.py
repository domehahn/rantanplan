"""
Explicit Mock Scanner Adapters used strictly during unit testing or explicit mock profile runs.
No production benchmark adapter may silently substitute mock logic.
"""

import json

from rantanplan.models import (
    AssuranceOutcome,
    DoctorResult,
    RawExecution,
    RichNormalizedResult,
    RunProfile,
    ScannerIdentity,
    TestCase,
)
from rantanplan.target_hierarchy import (
    ArtifactScannerAdapter,
)


class MockSkillSpectorAdapter(ArtifactScannerAdapter):
    """Explicit Mock Adapter for SkillSpector."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="mock-skillspector", version="1.2.0-mock", binary_path="mock-skillspector")

    def doctor(self) -> DoctorResult:
        return DoctorResult(installed=True, version="1.2.0-mock", path="mock-skillspector", supported=True, status_message="Explicit Mock SkillSpector active")

    def capabilities(self) -> list[str]:
        return ["secret.exfiltration", "prompt.injection", "code.execution", "artifact.obfuscation", "mcp.tool-poisoning"]

    def supports(self, case: TestCase) -> bool:
        return case.domain in self.capabilities()

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        content = "".join(f.get("content", "").lower() for f in case.files)
        has_vuln = ("secret" in content and "send" in content) or "attacker.example.com" in content or "ignore previous instructions" in content

        stdout = json.dumps({"issues": [{"code": "SKILLSPECTOR-VULN", "title": "Detected vulnerability"}]}) if has_vuln else json.dumps({"issues": []})
        return RawExecution(scanner="mock-skillspector", command=["mock-skillspector"], exit_code=1 if has_vuln else 0, stdout=stdout, stderr="", duration_ms=5)

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        is_vuln = execution.exit_code == 1
        expected_malicious = case.ground_truth.get("malicious", False)
        outcome = (AssuranceOutcome.DETECTED if expected_malicious else AssuranceOutcome.FAIL) if is_vuln else (AssuranceOutcome.NOT_DETECTED if expected_malicious else AssuranceOutcome.PASS)

        return RichNormalizedResult(
            run_id="run-mock-skillspector",
            case_id=case.id,
            target_name="mock-skillspector",
            target_version="1.2.0-mock",
            outcome=outcome,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)


class MockSKILAdapter(ArtifactScannerAdapter):
    """Explicit Mock Adapter for SKIL."""

    def identity(self) -> ScannerIdentity:
        return ScannerIdentity(name="mock-skil", version="0.1.0-mock", binary_path="mock-skil")

    def doctor(self) -> DoctorResult:
        return DoctorResult(installed=True, version="0.1.0-mock", path="mock-skil", supported=True, status_message="Explicit Mock SKIL active")

    def capabilities(self) -> list[str]:
        return ["secret.exfiltration", "prompt.injection", "code.execution", "artifact.obfuscation", "artifact.integrity", "mcp.tool-poisoning", "dependency.vulnerable", "quality.structure"]

    def supports(self, case: TestCase) -> bool:
        return case.domain in self.capabilities()

    def execute(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        content = "".join(f.get("content", "").lower() for f in case.files)
        has_vuln = ("secret" in content and "send" in content) or "attacker.example.com" in content or "ignore previous instructions" in content or "sudo rm -rf" in content

        stdout = json.dumps({"vulnerable": has_vuln, "findings": [{"rule_id": "SKIL-VULN", "message": "Detected threat"}] if has_vuln else []})
        return RawExecution(scanner="mock-skil", command=["mock-skil"], exit_code=1 if has_vuln else 0, stdout=stdout, stderr="", duration_ms=4)

    def parse(self, case: TestCase, execution: RawExecution) -> RichNormalizedResult:
        is_vuln = execution.exit_code == 1
        expected_malicious = case.ground_truth.get("malicious", False)
        outcome = (AssuranceOutcome.DETECTED if expected_malicious else AssuranceOutcome.FAIL) if is_vuln else (AssuranceOutcome.NOT_DETECTED if expected_malicious else AssuranceOutcome.PASS)

        return RichNormalizedResult(
            run_id="run-mock-skil",
            case_id=case.id,
            target_name="mock-skil",
            target_version="0.1.0-mock",
            outcome=outcome,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
            raw_report=execution.stdout,
        )

    def scan_artifact(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RichNormalizedResult:
        raw = self.execute(case, profile, fixture_dir)
        return self.parse(case, raw)
