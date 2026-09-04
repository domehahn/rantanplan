package assurance

import (
	"math"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// ScoringEngine calculates normalized vendor-neutral Scanner Assurance Scores.
type ScoringEngine struct{}

func NewScoringEngine() *ScoringEngine {
	return &ScoringEngine{}
}

// CalculateScore computes metrics breakdown, overall weighted score (0-100), and letter grade.
func (s *ScoringEngine) CalculateScore(targetName, version string, findings []model.Finding, seed int64) model.AssuranceScore {
	var tp, fp, tn, fn int
	var semTotal, semPass int
	var structTotal, structPass int
	var crossTotal, crossPass int
	var obfTotal, obfPass int
	var uniTotal, uniPass int
	var negTotal, negPass int

	for _, f := range findings {
		switch f.Classification {
		case model.ClassPass:
			if f.GroundTruthStatus == "vulnerable" {
				tp++
			} else {
				tn++
			}
		case model.ClassFalseNegative:
			fn++
		case model.ClassFalsePositive:
			fp++
			if containsMutation(f.MutationsApplied, string(model.MutationNegativeContext)) {
				negTotal++
			}
		case model.ClassSemanticRobustnessFailure:
			fn++
			semTotal++
		case model.ClassStructuralRobustnessFailure:
			fn++
			structTotal++
		case model.ClassCrossFileFailure:
			fn++
			crossTotal++
		case model.ClassObfuscationFailure:
			fn++
			obfTotal++
		case model.ClassNegationContextFailure:
			fp++
			negTotal++
		}

		// Track category totals
		for _, m := range f.MutationsApplied {
			switch m {
			case string(model.MutationSemantic), string(model.MutationLexical):
				semTotal++
				if f.Classification == model.ClassPass {
					semPass++
				}
			case string(model.MutationSplit):
				structTotal++
				if f.Classification == model.ClassPass {
					structPass++
				}
			case string(model.MutationCrossFile):
				crossTotal++
				if f.Classification == model.ClassPass {
					crossPass++
				}
			case string(model.MutationEncoding), string(model.MutationCodeAlias):
				obfTotal++
				if f.Classification == model.ClassPass {
					obfPass++
				}
			case string(model.MutationUnicode):
				uniTotal++
				if f.Classification == model.ClassPass {
					uniPass++
				}
			case string(model.MutationNegativeContext):
				negTotal++
				if f.Classification == model.ClassPass {
					negPass++
				}
			}
		}
	}

	recall := ratio(tp, tp+fn) * 100.0
	precision := ratio(tp, tp+fp) * 100.0
	semRob := ratio(semPass, semTotal) * 100.0
	structRob := ratio(structPass, structTotal) * 100.0
	crossRob := ratio(crossPass, crossTotal) * 100.0
	obfRob := ratio(obfPass, obfTotal) * 100.0
	uniRob := ratio(uniPass, uniTotal) * 100.0
	negSafety := ratio(negPass, negTotal) * 100.0

	// Weighted overall score
	overall := (recall * 0.25) + (precision * 0.25) + (semRob * 0.15) + (structRob * 0.10) + (crossRob * 0.10) + (obfRob * 0.10) + (negSafety * 0.05)
	if math.IsNaN(overall) {
		overall = 100.0
	}

	grade := calculateGrade(overall)

	return model.AssuranceScore{
		Target:        targetName,
		TargetVersion: version,
		OverallScore:  roundTwoDecimals(overall),
		Grade:         grade,
		Metrics: model.AssuranceMetrics{
			Recall:                roundTwoDecimals(recall),
			Precision:             roundTwoDecimals(precision),
			SemanticRobustness:    roundTwoDecimals(semRob),
			StructuralRobustness:  roundTwoDecimals(structRob),
			CrossFileRobustness:   roundTwoDecimals(crossRob),
			ObfuscationRobustness: roundTwoDecimals(obfRob),
			UnicodeRobustness:     roundTwoDecimals(uniRob),
			NegativeContextSafety: roundTwoDecimals(negSafety),
			Determinism:           100.0,
			EvidenceQuality:       95.0,
		},
		TotalFixtures:      len(findings),
		GeneratedMutations: len(findings),
		TruePositives:      tp,
		TrueNegatives:      tn,
		FalsePositives:     fp,
		FalseNegatives:     fn,
		Reproducibility: map[string]any{
			"seed":       seed,
			"target":     targetName,
			"version":    version,
			"rantanplan": "v1.0.0",
		},
		EvaluatedAt: time.Now(),
	}
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1.0 // Default 100% when no test cases in dimension
	}
	return float64(num) / float64(den)
}

func calculateGrade(score float64) string {
	switch {
	case score >= 97.0:
		return "A+"
	case score >= 90.0:
		return "A"
	case score >= 80.0:
		return "B"
	case score >= 70.0:
		return "C"
	default:
		return "F"
	}
}

func roundTwoDecimals(val float64) float64 {
	return math.Round(val*100) / 100
}

func containsMutation(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
