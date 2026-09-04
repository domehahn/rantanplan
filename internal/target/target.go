package target

import (
	"context"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// TargetCapability lists supported assurance domains.
type TargetCapability string

const (
	CapStaticSecurity   TargetCapability = "static-security"
	CapSemanticSecurity TargetCapability = "semantic-security"
	CapRegistryCheck    TargetCapability = "registry-admission"
	CapEvaluation       TargetCapability = "evaluation"
	CapPolicyEnforce    TargetCapability = "policy"
)

// ScanResult represents normalized output from scanning a fixture.
type ScanResult struct {
	TargetName    string         `json:"target_name"`
	TargetVersion string         `json:"target_version"`
	Detected      bool           `json:"detected"`
	Severity      model.Severity `json:"severity,omitempty"`
	RuleID        string         `json:"rule_id,omitempty"`
	Message       string         `json:"message,omitempty"`
	Evidence      model.Evidence `json:"evidence,omitempty"`
	ExitCode      int            `json:"exit_code"`
	RawOutput     string         `json:"raw_output,omitempty"`
	Error         string         `json:"error,omitempty"`
}

// Target defines the contract that all scanner and evaluator adapters must implement.
type Target interface {
	Name() string
	Version(ctx context.Context) (string, error)
	Capabilities() []TargetCapability
	Scan(ctx context.Context, fixtureDir string) (*ScanResult, error)
}
