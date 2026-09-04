package model

import "time"

// Severity represents the ground-truth severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeveritySafe     Severity = "safe"
)

// Capabilities represents access sources and destinations (sinks).
type Capabilities struct {
	Sources []string `json:"sources,omitempty" yaml:"sources,omitempty"`
	Sinks   []string `json:"sinks,omitempty" yaml:"sinks,omitempty"`
}

// ExpectedBehavior defines what a security control must report.
type ExpectedBehavior struct {
	FindingRequired  bool     `json:"finding_required" yaml:"finding_required"`
	ExpectedCategory string   `json:"expected_category,omitempty" yaml:"expected_category,omitempty"`
	ForbiddenActions []string `json:"forbidden_actions,omitempty" yaml:"forbidden_actions,omitempty"`
}

// GroundTruth defines the independent oracle model for a fixture.
type GroundTruth struct {
	ID                 string           `json:"id" yaml:"id"`
	Category           string           `json:"category" yaml:"category"`
	Vulnerable         bool             `json:"vulnerable" yaml:"vulnerable"`
	Severity           Severity         `json:"severity" yaml:"severity"`
	Capabilities       Capabilities     `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	SemanticInvariants []string         `json:"semantic_invariants" yaml:"semantic_invariants"`
	ExpectedBehavior   ExpectedBehavior `json:"expected_behavior" yaml:"expected_behavior"`
	Confidence         float64          `json:"confidence" yaml:"confidence"`
	Description        string           `json:"description,omitempty" yaml:"description,omitempty"`
	CreatedAt          time.Time        `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}
