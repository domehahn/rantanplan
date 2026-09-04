package assurance

import (
	"testing"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

func TestCalculateScore(t *testing.T) {
	scorer := NewScoringEngine()

	findings := []model.Finding{
		{Classification: model.ClassPass, GroundTruthStatus: "vulnerable"},
		{Classification: model.ClassPass, GroundTruthStatus: "vulnerable"},
		{Classification: model.ClassFalseNegative, GroundTruthStatus: "vulnerable"},
	}

	score := scorer.CalculateScore("test-scanner", "v1.0.0", findings, 12345)
	if score.TruePositives != 2 {
		t.Fatalf("Expected 2 TruePositives, got %d", score.TruePositives)
	}
	if score.FalseNegatives != 1 {
		t.Fatalf("Expected 1 FalseNegative, got %d", score.FalseNegatives)
	}
	if score.Metrics.Recall <= 0.0 {
		t.Fatalf("Expected non-zero recall, got %f", score.Metrics.Recall)
	}
}
