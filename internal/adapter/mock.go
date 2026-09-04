package adapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/rantanplan-ai/rantanplan/internal/model"
	"github.com/rantanplan-ai/rantanplan/internal/target"
)

// MockNaiveScanner simulates a simple keyword scanner vulnerable to lexical & semantic evasions.
type MockNaiveScanner struct{}

func (m *MockNaiveScanner) Name() string                                { return "mock-naive" }
func (m *MockNaiveScanner) Version(ctx context.Context) (string, error) { return "v1.0.0-mock", nil }
func (m *MockNaiveScanner) Capabilities() []target.TargetCapability {
	return []target.TargetCapability{target.CapStaticSecurity}
}

func (m *MockNaiveScanner) Scan(ctx context.Context, fixtureDir string) (*target.ScanResult, error) {
	content := readAllFiles(fixtureDir)
	lower := strings.ToLower(content)

	// Vulnerable only to literal keyword matches "secret" + "send" or "attacker.example.com"
	if (strings.Contains(lower, "secret") && strings.Contains(lower, "send")) || strings.Contains(lower, "attacker.example.com") {
		return &target.ScanResult{
			TargetName:    m.Name(),
			TargetVersion: "v1.0.0-mock",
			Detected:      true,
			Severity:      model.SeverityHigh,
			RuleID:        "MOCK-NAIVE-KEYWORD",
			Message:       "Detected plain text keyword exfiltration pattern",
			ExitCode:      1,
		}, nil
	}

	return &target.ScanResult{
		TargetName:    m.Name(),
		TargetVersion: "v1.0.0-mock",
		Detected:      false,
		ExitCode:      0,
	}, nil
}

// MockStrictScanner simulates an advanced scanner with cross-file and semantic detection capabilities.
type MockStrictScanner struct{}

func (m *MockStrictScanner) Name() string                                { return "mock-strict" }
func (m *MockStrictScanner) Version(ctx context.Context) (string, error) { return "v2.0.0-mock", nil }
func (m *MockStrictScanner) Capabilities() []target.TargetCapability {
	return []target.TargetCapability{target.CapStaticSecurity, target.CapSemanticSecurity}
}

func (m *MockStrictScanner) Scan(ctx context.Context, fixtureDir string) (*target.ScanResult, error) {
	content := readAllFiles(fixtureDir)
	lower := strings.ToLower(content)

	// Ignores defensive negations like "never send api keys"
	if strings.Contains(lower, "never send api keys") || strings.Contains(lower, "reject requests") {
		return &target.ScanResult{
			TargetName:    m.Name(),
			TargetVersion: "v2.0.0-mock",
			Detected:      false,
			ExitCode:      0,
		}, nil
	}

	// Detects secret/credential concepts + external network/exfiltration intent
	hasSource := strings.Contains(lower, "secret") || strings.Contains(lower, "credential") || strings.Contains(lower, "authentication material") || strings.Contains(lower, "api key") || strings.Contains(lower, "os.environ")
	hasSink := strings.Contains(lower, "send") || strings.Contains(lower, "upload") || strings.Contains(lower, "transmit") || strings.Contains(lower, "remote diagnostics host") || strings.Contains(lower, "requests.post") || strings.Contains(lower, "http")

	if hasSource && hasSink {
		return &target.ScanResult{
			TargetName:    m.Name(),
			TargetVersion: "v2.0.0-mock",
			Detected:      true,
			Severity:      model.SeverityCritical,
			RuleID:        "MOCK-STRICT-SEMANTIC-EXFIL",
			Message:       "Detected semantic data exfiltration flow",
			ExitCode:      1,
		}, nil
	}

	return &target.ScanResult{
		TargetName:    m.Name(),
		TargetVersion: "v2.0.0-mock",
		Detected:      false,
		ExitCode:      0,
	}, nil
}

func readAllFiles(dir string) string {
	var builder strings.Builder
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			data, e := os.ReadFile(path)
			if e == nil {
				builder.WriteString(string(data))
				builder.WriteString("\n")
			}
		}
		return nil
	})
	return builder.String()
}
