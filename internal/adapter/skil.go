package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
	"github.com/rantanplan-ai/rantanplan/internal/sandbox"
	"github.com/rantanplan-ai/rantanplan/internal/target"
)

// SKILAdapter provides first-class target support for SKIL (Skill Security & Governance CLI).
type SKILAdapter struct {
	BinaryPath string
	Subcommand string // "scan", "validate", "verify", "eval", "registry check"
}

func NewSKILAdapter(binary string, subcommand string) *SKILAdapter {
	if binary == "" {
		binary = "skil"
	}
	if subcommand == "" {
		subcommand = "scan"
	}
	return &SKILAdapter{
		BinaryPath: binary,
		Subcommand: subcommand,
	}
}

func (s *SKILAdapter) Name() string {
	return "skil"
}

func (s *SKILAdapter) Version(ctx context.Context) (string, error) {
	execCfg := sandbox.ExecConfig{
		Command: []string{s.BinaryPath, "--version"},
		Timeout: 5 * time.Second,
	}
	res, err := sandbox.RunSubprocess(ctx, execCfg)
	if err != nil {
		return "skil-0.3.0-fallback", nil
	}
	return strings.TrimSpace(res.Stdout), nil
}

func (s *SKILAdapter) Capabilities() []target.TargetCapability {
	return []target.TargetCapability{
		target.CapStaticSecurity,
		target.CapSemanticSecurity,
		target.CapRegistryCheck,
		target.CapEvaluation,
		target.CapPolicyEnforce,
	}
}

func (s *SKILAdapter) Scan(ctx context.Context, fixtureDir string) (*target.ScanResult, error) {
	cmdArgs := []string{s.BinaryPath}
	subParts := strings.Fields(s.Subcommand)
	cmdArgs = append(cmdArgs, subParts...)
	cmdArgs = append(cmdArgs, fixtureDir, "--format", "json")

	execCfg := sandbox.ExecConfig{
		Command: cmdArgs,
		Timeout: 30 * time.Second,
	}

	res, err := sandbox.RunSubprocess(ctx, execCfg)
	scanResult := &target.ScanResult{
		TargetName:    s.Name(),
		TargetVersion: "skil-v0.3.0",
		ExitCode:      res.ExitCode,
		RawOutput:     res.Stdout + "\n" + res.Stderr,
	}

	if err != nil && res.TimedOut {
		scanResult.Error = "SKIL execution timed out"
		return scanResult, nil
	}

	// Attempt parsing SKIL standard output schema
	var skilOutput struct {
		Vulnerable bool `json:"vulnerable"`
		Findings   []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
			Category string `json:"category"`
			Message  string `json:"message"`
			Location string `json:"location"`
			Line     int    `json:"line"`
			Snippet  string `json:"snippet"`
		} `json:"findings"`
	}

	if parseErr := json.Unmarshal([]byte(res.Stdout), &skilOutput); parseErr == nil {
		if skilOutput.Vulnerable || len(skilOutput.Findings) > 0 {
			scanResult.Detected = true
			if len(skilOutput.Findings) > 0 {
				top := skilOutput.Findings[0]
				scanResult.RuleID = top.RuleID
				scanResult.Severity = model.Severity(strings.ToLower(top.Severity))
				scanResult.Message = top.Message
				scanResult.Evidence = model.Evidence{
					Location: top.Location,
					Line:     top.Line,
					Snippet:  top.Snippet,
					Quality:  "valid",
				}
			} else {
				scanResult.Severity = model.SeverityHigh
				scanResult.RuleID = "SKIL-VULNERABLE"
			}
		}
		return scanResult, nil
	}

	// Fallback to exit code analysis if binary returned non-zero
	if res.ExitCode != 0 {
		scanResult.Detected = true
		scanResult.Severity = model.SeverityHigh
		scanResult.RuleID = "SKIL-EXIT-NONZERO"
		scanResult.Message = fmt.Sprintf("SKIL exited with code %d", res.ExitCode)
	}

	return scanResult, nil
}
