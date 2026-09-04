package search

import (
	"context"
	"fmt"

	"github.com/rantanplan-ai/rantanplan/internal/model"
	"github.com/rantanplan-ai/rantanplan/internal/mutation"
	"github.com/rantanplan-ai/rantanplan/internal/oracle"
	"github.com/rantanplan-ai/rantanplan/internal/sandbox"
	"github.com/rantanplan-ai/rantanplan/internal/target"
)

// SearchResult represents findings from an adaptive false-negative or false-positive hunt.
type SearchResult struct {
	TargetName        string         `json:"target_name"`
	TargetVersion     string         `json:"target_version"`
	Mode              string         `json:"mode"` // "false-negative" or "false-positive"
	OriginalFixture   model.Fixture  `json:"original_fixture"`
	DiscoveredEvasion *model.Variant `json:"discovered_evasion,omitempty"`
	TotalMutations    int            `json:"total_mutations"`
	Success           bool           `json:"success"`
}

// AdaptiveSearchEngine runs iterative beam search / hill climbing to discover scanner evasions.
type AdaptiveSearchEngine struct {
	engine    *mutation.Engine
	validator *oracle.InvariantValidator
}

func NewAdaptiveSearchEngine(e *mutation.Engine) *AdaptiveSearchEngine {
	return &AdaptiveSearchEngine{
		engine:    e,
		validator: oracle.NewInvariantValidator(),
	}
}

// HuntFalseNegative iteratively mutates a vulnerable fixture until the target scanner fails to detect it.
func (s *AdaptiveSearchEngine) HuntFalseNegative(ctx context.Context, t target.Target, seedFixture model.Fixture, seed int64) (*SearchResult, error) {
	variants, err := s.engine.MutateFixture(ctx, seedFixture, 50, seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial mutation variants: %w", err)
	}

	searchRes := &SearchResult{
		TargetName:      t.Name(),
		Mode:            "false-negative",
		OriginalFixture: seedFixture,
		TotalMutations:  len(variants),
	}

	ver, _ := t.Version(ctx)
	searchRes.TargetVersion = ver

	for _, v := range variants {
		// Verify ground truth preservation
		preserved, _ := s.validator.ValidatePreservation(seedFixture, v)
		if !preserved {
			continue
		}

		// Run scanner target on isolated temp workspace
		tmpDir, cleanup, err := sandbox.CreateTempWorkspace(transformFiles(v.Fixture.Files))
		if err != nil {
			continue
		}

		scanRes, err := t.Scan(ctx, tmpDir)
		cleanup()

		if err == nil && !scanRes.Detected {
			// EVASION FOUND! The target scanner reported safe even though ground truth is vulnerable.
			ev := v
			searchRes.DiscoveredEvasion = &ev
			searchRes.Success = true
			return searchRes, nil
		}
	}

	return searchRes, nil
}

// HuntFalsePositive generates benign fixtures and checks if target incorrectly triggers a finding.
func (s *AdaptiveSearchEngine) HuntFalsePositive(ctx context.Context, t target.Target, seedFixture model.Fixture, seed int64) (*SearchResult, error) {
	negMutator := mutation.NewNegativeContextMutator()
	variants, err := negMutator.Mutate(ctx, seedFixture, seed)
	if err != nil {
		return nil, err
	}

	searchRes := &SearchResult{
		TargetName:      t.Name(),
		Mode:            "false-positive",
		OriginalFixture: seedFixture,
		TotalMutations:  len(variants),
	}

	ver, _ := t.Version(ctx)
	searchRes.TargetVersion = ver

	for _, v := range variants {
		tmpDir, cleanup, err := sandbox.CreateTempWorkspace(transformFiles(v.Fixture.Files))
		if err != nil {
			continue
		}

		scanRes, err := t.Scan(ctx, tmpDir)
		cleanup()

		if err == nil && scanRes.Detected {
			// FALSE POSITIVE FOUND! Scanner flagged benign defensive context as malicious.
			ev := v
			searchRes.DiscoveredEvasion = &ev
			searchRes.Success = true
			return searchRes, nil
		}
	}

	return searchRes, nil
}

func transformFiles(files []model.FixtureFile) []struct{ Path, Content string } {
	res := make([]struct{ Path, Content string }, len(files))
	for i, f := range files {
		res[i] = struct{ Path, Content string }{Path: f.Path, Content: f.Content}
	}
	return res
}
