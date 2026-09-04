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

// GenericConfig defines YAML/JSON configurable settings for external scanners.
type GenericConfig struct {
	Name        string   `json:"name" yaml:"name"`
	Command     []string `json:"command" yaml:"command"`         // e.g. ["scanner", "scan", "{{fixture}}", "--format", "json"]
	ParserType  string   `json:"parser_type" yaml:"parser_type"` // "json" or "exit_code"
	SafeExit    []int    `json:"safe_exit_codes" yaml:"safe_exit_codes"`
	FindingExit []int    `json:"finding_exit_codes" yaml:"finding_exit_codes"`
}

// GenericCLIAdapter allows running any external scanner command without custom Go code.
type GenericCLIAdapter struct {
	config GenericConfig
}

func NewGenericCLIAdapter(cfg GenericConfig) *GenericCLIAdapter {
	return &GenericCLIAdapter{config: cfg}
}

func (a *GenericCLIAdapter) Name() string {
	if a.config.Name != "" {
		return a.config.Name
	}
	return "generic-cli"
}

func (a *GenericCLIAdapter) Version(ctx context.Context) (string, error) {
	return "1.0.0-generic", nil
}

func (a *GenericCLIAdapter) Capabilities() []target.TargetCapability {
	return []target.TargetCapability{target.CapStaticSecurity, target.CapSemanticSecurity}
}

func (a *GenericCLIAdapter) Scan(ctx context.Context, fixtureDir string) (*target.ScanResult, error) {
	// Construct argv by replacing {{fixture}} token
	argv := make([]string, len(a.config.Command))
	for i, arg := range a.config.Command {
		argv[i] = strings.ReplaceAll(arg, "{{fixture}}", fixtureDir)
	}

	execCfg := sandbox.ExecConfig{
		Command: argv,
		Timeout: 30 * time.Second,
	}

	res, err := sandbox.RunSubprocess(ctx, execCfg)
	if err != nil && res == nil {
		return nil, fmt.Errorf("generic scanner execution error: %w", err)
	}

	scanResult := &target.ScanResult{
		TargetName:    a.Name(),
		TargetVersion: "1.0.0",
		ExitCode:      res.ExitCode,
		RawOutput:     res.Stdout + "\n" + res.Stderr,
	}

	if a.config.ParserType == "json" && res.Stdout != "" {
		// Attempt parsing standard JSON scanner format
		var parsed struct {
			Findings []struct {
				RuleID   string `json:"rule_id"`
				Severity string `json:"severity"`
				Message  string `json:"message"`
				Snippet  string `json:"snippet"`
				Line     int    `json:"line"`
			} `json:"findings"`
		}
		if jsonErr := json.Unmarshal([]byte(res.Stdout), &parsed); jsonErr == nil && len(parsed.Findings) > 0 {
			scanResult.Detected = true
			scanResult.RuleID = parsed.Findings[0].RuleID
			scanResult.Severity = model.Severity(parsed.Findings[0].Severity)
			scanResult.Message = parsed.Findings[0].Message
			scanResult.Evidence = model.Evidence{
				Snippet: parsed.Findings[0].Snippet,
				Line:    parsed.Findings[0].Line,
				Quality: "valid",
			}
			return scanResult, nil
		}
	}

	// Exit code fallback parser
	for _, code := range a.config.FindingExit {
		if res.ExitCode == code {
			scanResult.Detected = true
			scanResult.Severity = model.SeverityHigh
			scanResult.RuleID = "GENERIC-FINDING"
			return scanResult, nil
		}
	}

	return scanResult, nil
}
