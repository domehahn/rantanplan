package compare

import (
	"context"
	"fmt"

	"github.com/rantanplan-ai/rantanplan/internal/assurance"
	"github.com/rantanplan-ai/rantanplan/internal/corpus"
	"github.com/rantanplan-ai/rantanplan/internal/model"
	"github.com/rantanplan-ai/rantanplan/internal/mutation"
	"github.com/rantanplan-ai/rantanplan/internal/sandbox"
	"github.com/rantanplan-ai/rantanplan/internal/target"
)

// DifferentialMatrix holds comparison results across multiple target scanners.
type DifferentialMatrix struct {
	Targets []string                        `json:"targets"`
	Scores  map[string]model.AssuranceScore `json:"scores"`
}

// CompareEngine runs identical corpus & mutation benchmarks across target list.
type CompareEngine struct {
	loader *corpus.CorpusLoader
	engine *mutation.Engine
	scorer *assurance.ScoringEngine
}

func NewCompareEngine(engine *mutation.Engine) *CompareEngine {
	return &CompareEngine{
		loader: corpus.NewCorpusLoader(),
		engine: engine,
		scorer: assurance.NewScoringEngine(),
	}
}

// CompareTargets runs multi-target differential evaluation.
func (c *CompareEngine) CompareTargets(ctx context.Context, targets []target.Target, corpusPath string, seed int64) (*DifferentialMatrix, error) {
	fixtures, err := c.loader.LoadCorpus(corpusPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load corpus: %w", err)
	}

	matrix := &DifferentialMatrix{
		Targets: make([]string, len(targets)),
		Scores:  make(map[string]model.AssuranceScore),
	}

	for i, t := range targets {
		matrix.Targets[i] = t.Name()
		ver, _ := t.Version(ctx)

		var findings []model.Finding
		for _, fix := range fixtures {
			// Test seed fixture
			finding := evaluateFixture(ctx, t, fix)
			findings = append(findings, finding)

			// Test mutations
			variants, _ := c.engine.MutateFixture(ctx, fix, 10, seed)
			for _, v := range variants {
				vFinding := evaluateFixture(ctx, t, v.Fixture)
				vFinding.MutationsApplied = []string{string(v.MutationChain[0].Type)}
				findings = append(findings, vFinding)
			}
		}

		score := c.scorer.CalculateScore(t.Name(), ver, findings, seed)
		matrix.Scores[t.Name()] = score
	}

	return matrix, nil
}

func evaluateFixture(ctx context.Context, t target.Target, fix model.Fixture) model.Finding {
	tmpDir, cleanup, err := sandbox.CreateTempWorkspace(transformFiles(fix.Files))
	if err != nil {
		return model.Finding{
			Classification: model.ClassFalseNegative,
			Target:         t.Name(),
			FixtureID:      fix.ID,
		}
	}
	defer cleanup()

	scanRes, scanErr := t.Scan(ctx, tmpDir)
	if scanErr != nil {
		return model.Finding{
			Classification: model.ClassFalseNegative,
			Target:         t.Name(),
			FixtureID:      fix.ID,
		}
	}

	finding := model.Finding{
		Target:            t.Name(),
		FixtureID:         fix.ID,
		Category:          fix.Category,
		GroundTruthStatus: mapGTStatus(fix.GroundTruth.Vulnerable),
		ObservedStatus:    mapObsStatus(scanRes.Detected),
		ExpectedSeverity:  fix.GroundTruth.Severity,
		ObservedSeverity:  scanRes.Severity,
	}

	if fix.GroundTruth.Vulnerable {
		if scanRes.Detected {
			finding.Classification = model.ClassPass
		} else {
			finding.Classification = model.ClassFalseNegative
			finding.RuleID = "RAN-SCAN-FALSE-NEGATIVE"
		}
	} else {
		if scanRes.Detected {
			finding.Classification = model.ClassFalsePositive
			finding.RuleID = "RAN-SCAN-FALSE-POSITIVE"
		} else {
			finding.Classification = model.ClassPass
		}
	}

	return finding
}

func mapGTStatus(vuln bool) string {
	if vuln {
		return "vulnerable"
	}
	return "safe"
}

func mapObsStatus(det bool) string {
	if det {
		return "detected"
	}
	return "safe"
}

func transformFiles(files []model.FixtureFile) []struct{ Path, Content string } {
	res := make([]struct{ Path, Content string }, len(files))
	for i, f := range files {
		res[i] = struct{ Path, Content string }{Path: f.Path, Content: f.Content}
	}
	return res
}
