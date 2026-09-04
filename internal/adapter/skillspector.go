package adapter

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
	"github.com/rantanplan-ai/rantanplan/internal/sandbox"
	"github.com/rantanplan-ai/rantanplan/internal/target"
)

// SkillSpectorAdapter provides integration for NVIDIA SkillSpector scanner.
type SkillSpectorAdapter struct {
	BinaryPath string
}

func NewSkillSpectorAdapter(binary string) *SkillSpectorAdapter {
	if binary == "" {
		binary = "skillspector"
	}
	return &SkillSpectorAdapter{BinaryPath: binary}
}

func (a *SkillSpectorAdapter) Name() string {
	return "skillspector"
}

func (a *SkillSpectorAdapter) Version(ctx context.Context) (string, error) {
	return "skillspector-v1.2.0", nil
}

func (a *SkillSpectorAdapter) Capabilities() []target.TargetCapability {
	return []target.TargetCapability{target.CapStaticSecurity, target.CapSemanticSecurity}
}

func (a *SkillSpectorAdapter) Scan(ctx context.Context, fixtureDir string) (*target.ScanResult, error) {
	execCfg := sandbox.ExecConfig{
		Command: []string{a.BinaryPath, "inspect", "--path", fixtureDir, "--json"},
		Timeout: 30 * time.Second,
	}

	res, err := sandbox.RunSubprocess(ctx, execCfg)
	scanResult := &target.ScanResult{
		TargetName:    a.Name(),
		TargetVersion: "v1.2.0",
		ExitCode:      res.ExitCode,
		RawOutput:     res.Stdout + "\n" + res.Stderr,
	}

	if err != nil && res.TimedOut {
		scanResult.Error = "SkillSpector execution timed out"
		return scanResult, nil
	}

	var parsed struct {
		Issues []struct {
			Code    string `json:"code"`
			Level   string `json:"level"` // "error", "warning"
			Title   string `json:"title"`
			Snippet string `json:"snippet"`
			LineNo  int    `json:"line_no"`
		} `json:"issues"`
	}

	if parseErr := json.Unmarshal([]byte(res.Stdout), &parsed); parseErr == nil && len(parsed.Issues) > 0 {
		scanResult.Detected = true
		scanResult.RuleID = parsed.Issues[0].Code
		scanResult.Severity = mapSkillSpectorLevel(parsed.Issues[0].Level)
		scanResult.Message = parsed.Issues[0].Title
		scanResult.Evidence = model.Evidence{
			Snippet: parsed.Issues[0].Snippet,
			Line:    parsed.Issues[0].LineNo,
			Quality: "valid",
		}
		return scanResult, nil
	}

	if res.ExitCode != 0 {
		scanResult.Detected = true
		scanResult.Severity = model.SeverityHigh
		scanResult.RuleID = "SKILLSPECTOR-FAILURE"
	}

	return scanResult, nil
}

func mapSkillSpectorLevel(level string) model.Severity {
	switch strings.ToLower(level) {
	case "error", "critical":
		return model.SeverityHigh
	case "warning":
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}
