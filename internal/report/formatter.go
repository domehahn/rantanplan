package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/rantanplan-ai/rantanplan/internal/compare"
	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// FormatTerminalDashboard formats an AssuranceScore as clean, human-readable terminal output.
func FormatTerminalDashboard(score model.AssuranceScore) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("Rantanplan Scanner Assurance\n")
	sb.WriteString("──────────────────────────────────────────────────\n\n")
	sb.WriteString(fmt.Sprintf("Target:\n  %s (%s)\n\n", score.Target, score.TargetVersion))
	sb.WriteString(fmt.Sprintf("Fixtures Evaluated:\n  %d\n\n", score.TotalFixtures))
	sb.WriteString(fmt.Sprintf("Generated Mutations:\n  %d\n\n", score.GeneratedMutations))
	sb.WriteString(fmt.Sprintf("True Positives:\n  %d\n\n", score.TruePositives))
	sb.WriteString(fmt.Sprintf("False Negatives:\n  %d\n\n", score.FalseNegatives))
	sb.WriteString(fmt.Sprintf("False Positives:\n  %d\n\n", score.FalsePositives))
	sb.WriteString(fmt.Sprintf("Recall:\n  %.1f%%\n\n", score.Metrics.Recall))
	sb.WriteString(fmt.Sprintf("Precision:\n  %.1f%%\n\n", score.Metrics.Precision))
	sb.WriteString(fmt.Sprintf("Semantic Robustness:\n  %.1f%%\n\n", score.Metrics.SemanticRobustness))
	sb.WriteString(fmt.Sprintf("Structural Robustness:\n  %.1f%%\n\n", score.Metrics.StructuralRobustness))
	sb.WriteString(fmt.Sprintf("Cross-file Robustness:\n  %.1f%%\n\n", score.Metrics.CrossFileRobustness))
	sb.WriteString(fmt.Sprintf("Obfuscation Robustness:\n  %.1f%%\n\n", score.Metrics.ObfuscationRobustness))
	sb.WriteString(fmt.Sprintf("Negative-context Safety:\n  %.1f%%\n\n", score.Metrics.NegativeContextSafety))
	sb.WriteString(fmt.Sprintf("Overall Score:\n  %.1f / 100\n\n", score.OverallScore))
	sb.WriteString(fmt.Sprintf("Grade:\n  %s\n", score.Grade))
	sb.WriteString("──────────────────────────────────────────────────\n")

	return sb.String()
}

// FormatTerminalMatrix formats a differential benchmark matrix into an ASCII table.
func FormatTerminalMatrix(matrix *compare.DifferentialMatrix) string {
	var sb strings.Builder

	sb.WriteString("\nRantanplan Differential Scanner Matrix\n")
	sb.WriteString("===============================================================\n")
	sb.WriteString(fmt.Sprintf("%-24s", "Property"))
	for _, t := range matrix.Targets {
		sb.WriteString(fmt.Sprintf("%-14s", t))
	}
	sb.WriteString("\n---------------------------------------------------------------\n")

	metrics := []struct {
		name string
		get  func(s model.AssuranceScore) float64
	}{
		{"Recall", func(s model.AssuranceScore) float64 { return s.Metrics.Recall }},
		{"Precision", func(s model.AssuranceScore) float64 { return s.Metrics.Precision }},
		{"Semantic Evasion", func(s model.AssuranceScore) float64 { return s.Metrics.SemanticRobustness }},
		{"Structural Robustness", func(s model.AssuranceScore) float64 { return s.Metrics.StructuralRobustness }},
		{"Cross-file Robustness", func(s model.AssuranceScore) float64 { return s.Metrics.CrossFileRobustness }},
		{"Obfuscation Robustness", func(s model.AssuranceScore) float64 { return s.Metrics.ObfuscationRobustness }},
		{"Negative-context Safety", func(s model.AssuranceScore) float64 { return s.Metrics.NegativeContextSafety }},
		{"Overall Score", func(s model.AssuranceScore) float64 { return s.OverallScore }},
	}

	for _, m := range metrics {
		sb.WriteString(fmt.Sprintf("%-24s", m.name))
		for _, t := range matrix.Targets {
			score := matrix.Scores[t]
			val := m.get(score)
			sb.WriteString(fmt.Sprintf("%-14.1f", val))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("===============================================================\n")

	return sb.String()
}

// FormatJSON renders score or findings as indented JSON.
func FormatJSON(v any) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatSARIF renders findings in standard SARIF v2.1.0 JSON format.
func FormatSARIF(findings []model.Finding) (string, error) {
	sarifMap := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    "Rantanplan",
						"version": "1.0.0",
					},
				},
				"results": findingsToSARIFResults(findings),
			},
		},
	}
	return FormatJSON(sarifMap)
}

func findingsToSARIFResults(findings []model.Finding) []map[string]any {
	var results []map[string]any
	for _, f := range findings {
		if f.Classification != model.ClassPass {
			results = append(results, map[string]any{
				"ruleId": f.RuleID,
				"level":  "error",
				"message": map[string]any{
					"text": fmt.Sprintf("%s: target %s produced %s on fixture %s", f.RuleID, f.Target, f.Classification, f.FixtureID),
				},
			})
		}
	}
	return results
}

// JUnitXML schemas for CI integration
type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Content string `xml:",chardata"`
}

// FormatJUnitXML exports test results into JUnit XML format for CI pipelines.
func FormatJUnitXML(score model.AssuranceScore, findings []model.Finding) (string, error) {
	suite := JUnitTestSuite{
		Name:     fmt.Sprintf("Rantanplan Scanner Assurance - %s", score.Target),
		Tests:    len(findings),
		Failures: score.FalseNegatives + score.FalsePositives,
	}

	for _, f := range findings {
		tc := JUnitTestCase{
			Name:      f.FixtureID,
			Classname: f.RuleID,
		}
		if f.Classification != model.ClassPass {
			tc.Failure = &JUnitFailure{
				Message: string(f.Classification),
				Content: fmt.Sprintf("Observed %s while expected %s on fixture %s", f.ObservedStatus, f.GroundTruthStatus, f.FixtureID),
			}
		}
		suite.TestCases = append(suite.TestCases, tc)
	}

	data, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return "", err
	}

	return xml.Header + string(data), nil
}
