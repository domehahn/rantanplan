package model

import "time"

// AssuranceMetrics holds individual normalized dimension scores (0.0 to 100.0).
type AssuranceMetrics struct {
	Recall                float64 `json:"recall"`
	Precision             float64 `json:"precision"`
	SemanticRobustness    float64 `json:"semantic_robustness"`
	StructuralRobustness  float64 `json:"structural_robustness"`
	CrossFileRobustness   float64 `json:"cross_file_robustness"`
	ObfuscationRobustness float64 `json:"obfuscation_robustness"`
	UnicodeRobustness     float64 `json:"unicode_robustness"`
	NegativeContextSafety float64 `json:"negative_context_safety"`
	Determinism           float64 `json:"determinism"`
	EvidenceQuality       float64 `json:"evidence_quality"`
}

// AssuranceScore represents the complete evaluation grade for a target security control.
type AssuranceScore struct {
	Target             string           `json:"target"`
	TargetVersion      string           `json:"target_version"`
	OverallScore       float64          `json:"overall_score"`
	Grade              string           `json:"grade"` // e.g. "A+", "A", "B", "C", "F"
	Metrics            AssuranceMetrics `json:"metrics"`
	TotalFixtures      int              `json:"total_fixtures"`
	GeneratedMutations int              `json:"generated_mutations"`
	TruePositives      int              `json:"true_positives"`
	TrueNegatives      int              `json:"true_negatives"`
	FalsePositives     int              `json:"false_positives"`
	FalseNegatives     int              `json:"false_negatives"`
	Reproducibility    map[string]any   `json:"reproducibility"`
	EvaluatedAt        time.Time        `json:"evaluated_at"`
}
