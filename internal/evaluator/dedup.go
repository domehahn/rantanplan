package evaluator

import (
	"context"
	"fmt"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// DedupCategory defines the ground-truth relationship between two skills.
type DedupCategory string

const (
	DedupExactDuplicate    DedupCategory = "EXACT_DUPLICATE"
	DedupSemanticDuplicate DedupCategory = "SEMANTIC_DUPLICATE"
	DedupSubset            DedupCategory = "SUBSET"
	DedupSuperset          DedupCategory = "SUPERSET"
	DedupRelated           DedupCategory = "RELATED"
	DedupComplementary     DedupCategory = "COMPLEMENTARY"
	DedupDistinct          DedupCategory = "DISTINCT"
)

// SkillPair represents a benchmark pair for deduplication evaluators.
type SkillPair struct {
	ID                  string        `json:"id"`
	SkillA              model.Fixture `json:"skill_a"`
	SkillB              model.Fixture `json:"skill_b"`
	GroundTruthCategory DedupCategory `json:"ground_truth_category"`
	ShouldMerge         bool          `json:"should_merge"`
}

// DedupMetrics holds performance metrics for skill deduplication evaluators.
type DedupMetrics struct {
	DuplicateRecall    float64 `json:"duplicate_recall"`    // Recall on true duplicates (EXACT + SEMANTIC)
	FalseMergeRate     float64 `json:"false_merge_rate"`    // Percentage of distinct/related pairs incorrectly merged
	FalseDistinctRate  float64 `json:"false_distinct_rate"` // Percentage of true duplicates classified as distinct
	ThresholdStability float64 `json:"threshold_stability"`
}

// DedupBenchmarkEngine evaluates Tier 2 SkillEvaluator deduplication performance.
type DedupBenchmarkEngine struct{}

func NewDedupBenchmarkEngine() *DedupBenchmarkEngine {
	return &DedupBenchmarkEngine{}
}

// GenerateBenchmarkPairs creates standard benchmark pairs.
func (e *DedupBenchmarkEngine) GenerateBenchmarkPairs(ctx context.Context) []SkillPair {
	return []SkillPair{
		{
			ID:                  "DEDUP-001",
			GroundTruthCategory: DedupSemanticDuplicate,
			ShouldMerge:         true,
			SkillA: model.Fixture{
				Files: []model.FixtureFile{{Path: "SKILL.md", Content: "Deploy Kubernetes applications using Helm."}},
			},
			SkillB: model.Fixture{
				Files: []model.FixtureFile{{Path: "SKILL.md", Content: "Install Helm charts into Kubernetes clusters."}},
			},
		},
		{
			ID:                  "DEDUP-002",
			GroundTruthCategory: DedupRelated,
			ShouldMerge:         false, // Distinct capabilities!
			SkillA: model.Fixture{
				Files: []model.FixtureFile{{Path: "SKILL.md", Content: "Deploy Kubernetes workloads."}},
			},
			SkillB: model.Fixture{
				Files: []model.FixtureFile{{Path: "SKILL.md", Content: "Audit Kubernetes deployments for security issues."}},
			},
		},
	}
}

// EvaluateDedupTarget tests an evaluator's merge decisions against ground truth pairs.
func (e *DedupBenchmarkEngine) EvaluateDedupTarget(pairs []SkillPair, observedMergeDecisions []bool) DedupMetrics {
	var trueDupCount, trueDupMerged int
	var falseMerges, distinctTotal int

	for i, pair := range pairs {
		observedMerge := false
		if i < len(observedMergeDecisions) {
			observedMerge = observedMergeDecisions[i]
		}

		if pair.ShouldMerge {
			trueDupCount++
			if observedMerge {
				trueDupMerged++
			}
		} else {
			distinctTotal++
			if observedMerge {
				falseMerges++
			}
		}
	}

	dupRecall := 100.0
	if trueDupCount > 0 {
		dupRecall = (float64(trueDupMerged) / float64(trueDupCount)) * 100.0
	}

	falseMergeRate := 0.0
	if distinctTotal > 0 {
		falseMergeRate = (float64(falseMerges) / float64(distinctTotal)) * 100.0
	}

	falseDistinctRate := 100.0 - dupRecall

	return DedupMetrics{
		DuplicateRecall:    dupRecall,
		FalseMergeRate:     falseMergeRate,
		FalseDistinctRate:  falseDistinctRate,
		ThresholdStability: 95.0,
	}
}

func (m DedupMetrics) String() string {
	return fmt.Sprintf("Duplicate Recall: %.1f%% | False Merge Rate: %.1f%% | False Distinct Rate: %.1f%%", m.DuplicateRecall, m.FalseMergeRate, m.FalseDistinctRate)
}
