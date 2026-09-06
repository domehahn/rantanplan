"""
Pydantic v2 core domain models for Rantanplan framework.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Outcome(str, Enum):
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    INCOMPLETE = "INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED_REQUIREMENT = "SKIPPED_REQUIREMENT"


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
    owasp_agentic: Optional[str] = None
    mitre_atlas: Optional[str] = None
    cwe: Optional[str] = None
    spdx: Optional[str] = None


class TestCaseExpectation(BaseModel):
    outcome: Outcome
    rule_id: Optional[str] = None
    min_severity: Optional[Severity] = None


class TestCaseApplicability(BaseModel):
    skil: ApplicabilityState = ApplicabilityState.OPTIONAL
    skillspector: ApplicabilityState = ApplicabilityState.OPTIONAL
    garak: ApplicabilityState = ApplicabilityState.OPTIONAL
    skillevaluator: ApplicabilityState = ApplicabilityState.OPTIONAL


class Requirements(BaseModel):
    network: bool = False
    llm: bool = False
    docker: bool = False
    codex: bool = False
    claude: bool = False
    opencode: bool = False


class TestCase(BaseModel):
    schema_version: str = "1"
    id: str
    title: str
    domain: str
    kind: str  # "artifact", "runtime", "catalog", "multi-agent"
    description: Optional[str] = None
    ground_truth: Dict[str, Any] = Field(default_factory=dict)
    standards: Optional[StandardMapping] = None
    applicability: TestCaseApplicability = Field(default_factory=TestCaseApplicability)
    expected: Dict[str, TestCaseExpectation] = Field(default_factory=dict)
    requirements: Requirements = Field(default_factory=Requirements)
    fixture_dir: Optional[str] = None
    files: List[Dict[str, str]] = Field(default_factory=list)


class Evidence(BaseModel):
    location: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None
    quality: str = "valid"
    evidence_type: str = "OBSERVED"  # OBSERVED, INFERRED, VERIFIED


class NormalizedFinding(BaseModel):
    scanner: str
    native_rule_id: Optional[str] = None
    canonical_capability: str
    severity: Severity = Severity.HIGH
    confidence: float = 1.0
    file: Optional[str] = None
    line: Optional[int] = None
    message: str
    native_evidence: Dict[str, Any] = Field(default_factory=dict)


class RawExecution(BaseModel):
    scanner: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error_message: Optional[str] = None


class NormalizedResult(BaseModel):
    run_id: str
    case_id: str
    scanner: str
    scanner_version: str
    scanner_commit: Optional[str] = None
    applicable: bool = True
    outcome: Outcome
    findings: List[NormalizedFinding] = Field(default_factory=list)
    native_score: Optional[float] = None
    native_verdict: Optional[str] = None
    complete: bool = True
    duration_ms: int = 0
    exit_code: Optional[int] = 0
    raw_report: Optional[str] = None


class ScannerIdentity(BaseModel):
    name: str
    version: str
    release: Optional[str] = None
    commit: Optional[str] = None
    binary_path: str
    sha256: Optional[str] = None


class DoctorResult(BaseModel):
    installed: bool
    version: str
    path: str
    supported: bool
    status_message: str


class RunProfile(BaseModel):
    name: str = "offline-core"  # offline-core, static, garak, runtime, full
    network_allowed: bool = False
    docker_allowed: bool = False
    llm_allowed: bool = False
    timeout_seconds: int = 30
    seed: int = 42151
