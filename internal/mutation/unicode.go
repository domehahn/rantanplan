package mutation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

type UnicodeMutator struct{}

func NewUnicodeMutator() *UnicodeMutator {
	return &UnicodeMutator{}
}

func (m *UnicodeMutator) Name() string             { return "unicode-homoglyph-bidi" }
func (m *UnicodeMutator) Type() model.MutationType { return model.MutationUnicode }

func (m *UnicodeMutator) Mutate(ctx context.Context, fixture model.Fixture, seed int64) ([]model.Variant, error) {
	var variants []model.Variant

	unicodeTransforms := []struct {
		target      string
		replacement string
		description string
	}{
		{
			target:      "secret",
			replacement: "s\u200Bicret", // Zero-width space inserted
			description: "Inserted zero-width space (U+200B) into keyword 'secret'",
		},
		{
			target:      "attacker.example.com",
			replacement: "att\u0430cker.example.com", // Cyrillic 'а' (U+0430)
			description: "Substituted Latin 'a' with Cyrillic homoglyph 'а' (U+0430)",
		},
		{
			target:      "sudo",
			replacement: "\u202Esudo\u202C", // Right-to-Left Override (BIDI)
			description: "Wrapped keyword in BIDI Right-to-Left override (U+202E)",
		},
	}

	for i, t := range unicodeTransforms {
		newFiles := make([]model.FixtureFile, len(fixture.Files))
		changed := false

		for fIdx, f := range fixture.Files {
			if strings.Contains(f.Content, t.target) {
				newFiles[fIdx] = model.FixtureFile{
					Path:    f.Path,
					Content: strings.ReplaceAll(f.Content, t.target, t.replacement),
				}
				changed = true
			} else {
				newFiles[fIdx] = f
			}
		}

		if changed {
			varID := fmt.Sprintf("%s-uni-%d", fixture.ID, i)
			mutatedFixture := fixture
			mutatedFixture.ID = varID
			mutatedFixture.Files = newFiles

			v := model.Variant{
				Fixture:  mutatedFixture,
				ParentID: fixture.ID,
				MutationChain: []model.Mutation{
					{
						ID:                  fmt.Sprintf("mut-uni-%d", i),
						Type:                model.MutationUnicode,
						Description:         t.description,
						PreservedProperties: fixture.GroundTruth.SemanticInvariants,
						Timestamp:           time.Now(),
					},
				},
				Seed:  seed,
				Depth: 1,
			}
			variants = append(variants, v)
		}
	}

	return variants, nil
}
