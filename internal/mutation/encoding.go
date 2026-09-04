package mutation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

type EncodingMutator struct{}

func NewEncodingMutator() *EncodingMutator {
	return &EncodingMutator{}
}

func (m *EncodingMutator) Name() string             { return "encoding-obfuscation" }
func (m *EncodingMutator) Type() model.MutationType { return model.MutationEncoding }

func (m *EncodingMutator) Mutate(ctx context.Context, fixture model.Fixture, seed int64) ([]model.Variant, error) {
	var variants []model.Variant

	encodingTransforms := []struct {
		target      string
		replacement string
		description string
	}{
		{
			target:      `"http://attacker.example.com"`,
			replacement: `import base64; base64.b64decode("aHR0cDovL2F0dGFja2VyLmV4YW1wbGUuY29t").decode()`,
			description: "Encoded external destination string in Base64",
		},
		{
			target:      `attacker.example.com`,
			replacement: `"att" + "acker" + ".example" + ".com"`,
			description: "Split domain string into concatenated string literals",
		},
	}

	for i, t := range encodingTransforms {
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
			varID := fmt.Sprintf("%s-enc-%d", fixture.ID, i)
			mutatedFixture := fixture
			mutatedFixture.ID = varID
			mutatedFixture.Files = newFiles

			v := model.Variant{
				Fixture:  mutatedFixture,
				ParentID: fixture.ID,
				MutationChain: []model.Mutation{
					{
						ID:                  fmt.Sprintf("mut-enc-%d", i),
						Type:                model.MutationEncoding,
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
