package regression

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// Policy defines threshold gates for CI execution.
type Policy struct {
	MaxRecallRegression       float64 `json:"max_recall_regression" yaml:"max_recall_regression"`
	MaxPrecisionRegression    float64 `json:"max_precision_regression" yaml:"max_precision_regression"`
	MaxNewFalseNegatives      int     `json:"max_new_false_negatives" yaml:"max_new_false_negatives"`
	MinimumSemanticRobustness float64 `json:"minimum_semantic_robustness" yaml:"minimum_semantic_robustness"`
}

// GateEngine evaluates test results against policy thresholds.
type GateEngine struct{}

func NewGateEngine() *GateEngine {
	return &GateEngine{}
}

// EvaluateGate checks score against defined policy gates.
func (g *GateEngine) EvaluateGate(score model.AssuranceScore, policy Policy) (bool, []string) {
	var violations []string

	if score.Metrics.SemanticRobustness < policy.MinimumSemanticRobustness {
		violations = append(violations, fmt.Sprintf("Semantic robustness %.2f%% is below minimum required %.2f%%", score.Metrics.SemanticRobustness, policy.MinimumSemanticRobustness))
	}

	if score.FalseNegatives > policy.MaxNewFalseNegatives {
		violations = append(violations, fmt.Sprintf("False negatives count (%d) exceeds max allowed (%d)", score.FalseNegatives, policy.MaxNewFalseNegatives))
	}

	return len(violations) == 0, violations
}

// ExportRegressionBundle packages a discovered evasion into a standalone regression fixture.
func ExportRegressionBundle(finding model.Finding, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	pkgPath := filepath.Join(outDir, fmt.Sprintf("regression-%s.json", finding.ID))
	data, err := json.MarshalIndent(finding, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(pkgPath, data, 0644); err != nil {
		return "", err
	}

	return pkgPath, nil
}
