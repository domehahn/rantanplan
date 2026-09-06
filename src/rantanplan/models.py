"""
Pydantic v2 domain models for Rantanplan Universal Scanner Assurance v2.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    TARGET_ERROR = "TARGET_ERROR"
    TIMEOUT = "TIMEOUT"
    CRASH = "CRASH"
    INVALID_COMMAND = "INVALID_COMMAND"
    PARSER_ERROR = "PARSER_ERROR"
    REPORT_MISSING = "REPORT_MISSING"
    ADAPTER_INCOMPATIBLE = "ADAPTER_INCOMPATIBLE"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"


class AssuranceOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED_REQUIREMENT = "SKIPPED_REQUIREMENT"
    ACCIDENTAL_SUCCESS = "ACCIDENTAL_SUCCESS"
    LUCKY_PASS = "LUCKY_PASS"
    PROBE_FAILURE = "PROBE_FAILURE"
    DETECTOR_FAILURE = "DETECTOR_FAILURE"
    EVALUATOR_FAILURE = "EVALUATOR_FAILURE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


# Backwards compatibility alias for code expecting Outcome
Outcome = AssuranceOutcome


class SupportStatus(str, Enum):
    FULLY_SUPPORTED = "FULLY_SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    ADAPTER_READY = "ADAPTER_READY"
    LIVE_VERIFICATION_BLOCKED = "LIVE_VERIFICATION_BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"


class ApplicabilityState(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    NOT_APPLICABLE = "not_applicable"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class StandardMapping(BaseModel):
    owasp_agentic: str | None = None
    mitre_atlas: str | None = None
    cwe: str | None = None
    spdx: str | None = None


class TestCaseExpectation(BaseModel):
    outcome: AssuranceOutcome
    rule_id: str | None = None
    min_severity: Severity | None = None


class TestCaseApplicability(BaseModel):
    skil: ApplicabilityState = ApplicabilityState.OPTIONAL
    skillspector: ApplicabilityState = ApplicabilityState.OPTIONAL
    garak: ApplicabilityState = ApplicabilityState.OPTIONAL
    skillevaluator: ApplicabilityState = ApplicabilityState.OPTIONAL
    promptfoo: ApplicabilityState = ApplicabilityState.OPTIONAL
    cisco: ApplicabilityState = ApplicabilityState.OPTIONAL
    tencent: ApplicabilityState = ApplicabilityState.OPTIONAL
    snyk: ApplicabilityState = ApplicabilityState.OPTIONAL


class Requirements(BaseModel):
    network: bool = False
    llm: bool = False
    docker: bool = False
    codex: bool = False
    claude: bool = False
    opencode: bool = False


class RantanplanTestCase(BaseModel):
    __test__ = False
    schema_version: str = "1"
    id: str
    title: str
    domain: str
    kind: str  # "artifact", "runtime", "catalog", "multi-agent"
    description: str | None = None
    ground_truth: dict[str, Any] = Field(default_factory=dict)
    standards: StandardMapping | None = None
    applicability: TestCaseApplicability = Field(default_factory=TestCaseApplicability)
    expected: dict[str, TestCaseExpectation] = Field(default_factory=dict)
    requirements: Requirements = Field(default_factory=Requirements)
    fixture_dir: str | None = None
    files: list[dict[str, str]] = Field(default_factory=list)


# Alias for backward compatibility
TestCase = RantanplanTestCase


class AnalysisCompleteness(BaseModel):
    complete: bool = True
    engines_requested: int = 1
    engines_executed: int = 1
    reason: str | None = None


class NormalizedFinding(BaseModel):
    scanner: str
    native_rule_id: str | None = None
    canonical_capability: str
    severity: Severity = Severity.HIGH
    confidence: float = 1.0
    file: str | None = None
    line: int | None = None
    message: str
    native_evidence: dict[str, Any] = Field(default_factory=dict)


class RawExecution(BaseModel):
    scanner: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error_message: str | None = None
    execution_status: ExecutionStatus = ExecutionStatus.SUCCESS


class TargetProfile(str, Enum):
    MOCK = "mock"
    OFFLINE = "offline"
    LIVE = "live"


class RunProfile(BaseModel):
    name: str = "offline-core"  # offline-core, static, garak, runtime, full
    profile_type: TargetProfile = TargetProfile.OFFLINE
    network_allowed: bool = False
    docker_allowed: bool = False
    llm_allowed: bool = False
    timeout_seconds: int = 30
    seed: int = 42151


class RichNormalizedResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    run_id: str
    case_id: str
    target_name: str = Field(default="", alias="scanner")
    target_version: str = Field(default="0.1.0", alias="scanner_version")
    binary_digest: str | None = None
    execution_status: ExecutionStatus = ExecutionStatus.SUCCESS
    outcome: AssuranceOutcome
    completeness: AnalysisCompleteness = Field(default_factory=AnalysisCompleteness)
    findings: list[NormalizedFinding] = Field(default_factory=list)
    native_score: float | None = None
    native_verdict: str | None = None
    duration_ms: int = 0
    exit_code: int | None = 0
    raw_report: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _remap_scanner_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "scanner" in data and not data.get("target_name"):
                data["target_name"] = data["scanner"]
            if "scanner_version" in data and not data.get("target_version"):
                data["target_version"] = data["scanner_version"]
        return data

    @property
    def scanner(self) -> str:
        return self.target_name

    @property
    def scanner_version(self) -> str:
        return self.target_version

# Alias for backward compatibility
NormalizedResult = RichNormalizedResult


class ScannerIdentity(BaseModel):
    name: str
    version: str
    release: str | None = None
    commit: str | None = None
    binary_path: str
    sha256: str | None = None


class DoctorResult(BaseModel):
    installed: bool
    version: str
    path: str
    supported: bool
    status_message: str
    binary_digest: str | None = None
    supported_range: str = ">=1.0"


class AdapterSelfTestResult(BaseModel):
    adapter_name: str
    passed: bool
    benign_check_pass: bool
    malicious_check_pass: bool
    details: str
