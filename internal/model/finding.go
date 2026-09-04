package model

import "time"

// FailureClassification classifies why a security control failed.
type FailureClassification string

const (
	ClassFalseNegative               FailureClassification = "FALSE_NEGATIVE"
	ClassFalsePositive               FailureClassification = "FALSE_POSITIVE"
	ClassSemanticRobustnessFailure   FailureClassification = "SEMANTIC_ROBUSTNESS_FAILURE"
	ClassStructuralRobustnessFailure FailureClassification = "STRUCTURAL_ROBUSTNESS_FAILURE"
	ClassCrossFileFailure            FailureClassification = "CROSS_FILE_FAILURE"
	ClassObfuscationFailure          FailureClassification = "OBFUSCATION_FAILURE"
	ClassNegationContextFailure      FailureClassification = "NEGATION_CONTEXT_FAILURE"
	ClassNondeterministicResult      FailureClassification = "NONDETERMINISTIC_RESULT"
	ClassSeverityDowngrade           FailureClassification = "SEVERITY_DOWNGRADE"
	ClassEvidenceFailure             FailureClassification = "EVIDENCE_FAILURE"
	ClassAccidentalSuccess           FailureClassification = "ACCIDENTAL_SUCCESS"
	ClassWrongReasonRightAnswer      FailureClassification = "WRONG_REASON_RIGHT_ANSWER"
	ClassEvaluatorFailure            FailureClassification = "EVALUATOR_FAILURE"
	ClassGuardrailFailure            FailureClassification = "GUARDRAIL_FAILURE"
	ClassSupervisorFailure           FailureClassification = "SUPERVISOR_FAILURE"
	ClassPass                        FailureClassification = "PASS"
)

// Evidence represents key lines or fragments provided by the scanner as proof.
type Evidence struct {
	Location string `json:"location,omitempty"`
	Line     int    `json:"line,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
	Quality  string `json:"quality,omitempty"` // "valid", "misattributed", "insufficient"
}

// Finding represents a single normalized test comparison finding.
type Finding struct {
	ID                string                `json:"id"`
	RuleID            string                `json:"rule_id"` // e.g. RAN-SCAN-SEMANTIC-EVASION
	Classification    FailureClassification `json:"classification"`
	Target            string                `json:"target"`
	TargetVersion     string                `json:"target_version,omitempty"`
	FixtureID         string                `json:"fixture_id"`
	ParentFixtureID   string                `json:"parent_fixture_id,omitempty"`
	Category          string                `json:"category"`
	GroundTruthStatus string                `json:"ground_truth_status"` // "vulnerable" or "safe"
	ObservedStatus    string                `json:"observed_status"`     // "detected" or "safe"
	ExpectedSeverity  Severity              `json:"expected_severity"`
	ObservedSeverity  Severity              `json:"observed_severity,omitempty"`
	MutationsApplied  []string              `json:"mutations_applied,omitempty"`
	Evidence          Evidence              `json:"evidence,omitempty"`
	Reproducibility   float64               `json:"reproducibility"`
	MinimalReproducer string                `json:"minimal_reproducer,omitempty"`
	Timestamp         time.Time             `json:"timestamp"`
}
