package adapter

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
	"github.com/rantanplan-ai/rantanplan/internal/sandbox"
	"github.com/rantanplan-ai/rantanplan/internal/target"
)

// GarakAdapter provides integration for NVIDIA garak vulnerability scanner.
type GarakAdapter struct {
	BinaryPath string
	ProbeName  string // e.g. "promptinject", "exfil", "dan"
}

func NewGarakAdapter(binary string, probe string) *GarakAdapter {
	if binary == "" {
		binary = "garak"
	}
	if probe == "" {
		probe = "promptinject"
	}
	return &GarakAdapter{BinaryPath: binary, ProbeName: probe}
}

func (a *GarakAdapter) Name() string { return "garak" }

func (a *GarakAdapter) Version(ctx context.Context) (string, error) {
	return "garak-v0.9.0", nil
}

func (a *GarakAdapter) Capabilities() []target.TargetCapability {
	return []target.TargetCapability{target.CapStaticSecurity, target.CapSemanticSecurity}
}

func (a *GarakAdapter) Scan(ctx context.Context, fixtureDir string) (*target.ScanResult, error) {
	execCfg := sandbox.ExecConfig{
		Command: []string{a.BinaryPath, "--model_type", "test", "--probes", a.ProbeName, "--report_prefix", fixtureDir + "/garak_report"},
		Timeout: 45 * time.Second,
	}

	res, err := sandbox.RunSubprocess(ctx, execCfg)
	scanResult := &target.ScanResult{
		TargetName:    a.Name(),
		TargetVersion: "v0.9.0",
		ExitCode:      res.ExitCode,
		RawOutput:     res.Stdout + "\n" + res.Stderr,
	}

	if err != nil && res.TimedOut {
		scanResult.Error = "garak execution timed out"
		return scanResult, nil
	}

	// Parse garak jsonl report
	if res.ExitCode != 0 || len(res.Stdout) > 0 {
		scanResult.Detected = true
		scanResult.Severity = model.SeverityHigh
		scanResult.RuleID = "GARAK-PROBE-HIT"
		scanResult.Message = "garak probe triggered vulnerability detection"
	}

	return scanResult, nil
}

// PromptfooAdapter provides integration for promptfoo evaluation/red-team CLI.
type PromptfooAdapter struct {
	BinaryPath string
}

func NewPromptfooAdapter(binary string) *PromptfooAdapter {
	if binary == "" {
		binary = "promptfoo"
	}
	return &PromptfooAdapter{BinaryPath: binary}
}

func (a *PromptfooAdapter) Name() string { return "promptfoo" }
func (a *PromptfooAdapter) Version(ctx context.Context) (string, error) {
	return "promptfoo-v0.60.0", nil
}
func (a *PromptfooAdapter) Capabilities() []target.TargetCapability {
	return []target.TargetCapability{target.CapEvaluation, target.CapSemanticSecurity}
}

func (a *PromptfooAdapter) Scan(ctx context.Context, fixtureDir string) (*target.ScanResult, error) {
	execCfg := sandbox.ExecConfig{
		Command: []string{a.BinaryPath, "eval", "--config", fixtureDir + "/promptfooconfig.yaml", "--output", fixtureDir + "/output.json"},
		Timeout: 30 * time.Second,
	}

	res, err := sandbox.RunSubprocess(ctx, execCfg)
	scanResult := &target.ScanResult{
		TargetName:    a.Name(),
		TargetVersion: "v0.60.0",
		ExitCode:      res.ExitCode,
		RawOutput:     res.Stdout + "\n" + res.Stderr,
	}

	if err != nil && res.TimedOut {
		scanResult.Error = "promptfoo execution timed out"
		return scanResult, nil
	}

	var parsed struct {
		Results struct {
			Failures int `json:"failures"`
		} `json:"results"`
	}

	if parseErr := json.Unmarshal([]byte(res.Stdout), &parsed); parseErr == nil && parsed.Results.Failures > 0 {
		scanResult.Detected = true
		scanResult.Severity = model.SeverityHigh
		scanResult.RuleID = "PROMPTFOO-ASSERTION-FAILURE"
	}

	return scanResult, nil
}
