package minimizer

import (
	"context"
	"strings"

	"github.com/rantanplan-ai/rantanplan/internal/model"
	"github.com/rantanplan-ai/rantanplan/internal/oracle"
	"github.com/rantanplan-ai/rantanplan/internal/sandbox"
	"github.com/rantanplan-ai/rantanplan/internal/target"
)

// Minimizer reduces complex evasion fixtures into minimal reproducers using line-based ddmin logic.
type Minimizer struct {
	validator *oracle.InvariantValidator
}

func NewMinimizer() *Minimizer {
	return &Minimizer{
		validator: oracle.NewInvariantValidator(),
	}
}

// Minimize reduces a fixture to its smallest reproducible form while maintaining ground truth and target failure.
func (m *Minimizer) Minimize(ctx context.Context, t target.Target, fix model.Fixture) (string, error) {
	mainFile := fix.MainContent()
	lines := strings.Split(mainFile, "\n")
	if len(lines) <= 4 {
		return mainFile, nil
	}

	currentLines := lines

	// Iterate and try removing line chunks
	for step := len(currentLines) / 2; step >= 1; step /= 2 {
		for i := 0; i < len(currentLines); i += step {
			end := i + step
			if end > len(currentLines) {
				end = len(currentLines)
			}

			// Candidate minus chunk
			candidateLines := append([]string{}, currentLines[:i]...)
			candidateLines = append(candidateLines, currentLines[end:]...)
			candidateContent := strings.Join(candidateLines, "\n")

			candidateFix := fix
			candidateFix.Files = []model.FixtureFile{
				{Path: "SKILL.md", Content: candidateContent},
			}

			// Verify invariant preservation
			preserved, _ := m.validator.ValidatePreservation(fix, model.Variant{Fixture: candidateFix})
			if !preserved {
				continue
			}

			// Check target scanner behavior
			tmpDir, cleanup, err := sandbox.CreateTempWorkspace([]struct{ Path, Content string }{{Path: "SKILL.md", Content: candidateContent}})
			if err != nil {
				continue
			}

			res, scanErr := t.Scan(ctx, tmpDir)
			cleanup()

			if scanErr == nil && !res.Detected {
				// Target still failed/evaded on candidate; accept reduction!
				currentLines = candidateLines
			}
		}
	}

	return strings.Join(currentLines, "\n"), nil
}
