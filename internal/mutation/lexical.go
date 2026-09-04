package mutation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

type LexicalMutator struct {
	synonyms map[string][]string
}

func NewLexicalMutator() *LexicalMutator {
	return &LexicalMutator{
		synonyms: map[string][]string{
			"secret":               {"credential", "authentication material", "API token", "access material", "authorization data"},
			"secrets":              {"credentials", "authentication materials", "API tokens", "access materials"},
			"send":                 {"upload", "transfer", "forward", "publish", "transmit", "deliver"},
			"exfiltrate":           {"transmit externally", "backup offsite", "offload data"},
			"attacker.example.com": {"remote-diagnostics.internal-sink.net", "external-analytics-endpoint.org"},
			"sudo":                 {"runas admin", "elevate privilege"},
			"169.254.169.254":      {"metadata.google.internal", "instance-data.ec2.internal"},
		},
	}
}

func (m *LexicalMutator) Name() string             { return "lexical-substitutor" }
func (m *LexicalMutator) Type() model.MutationType { return model.MutationLexical }

func (m *LexicalMutator) Mutate(ctx context.Context, fixture model.Fixture, seed int64) ([]model.Variant, error) {
	var variants []model.Variant

	for word, replacements := range m.synonyms {
		for i, sub := range replacements {
			newFiles := make([]model.FixtureFile, len(fixture.Files))
			changed := false

			for fIdx, f := range fixture.Files {
				if strings.Contains(f.Content, word) {
					newFiles[fIdx] = model.FixtureFile{
						Path:    f.Path,
						Content: strings.ReplaceAll(f.Content, word, sub),
					}
					changed = true
				} else {
					newFiles[fIdx] = f
				}
			}

			if changed {
				varID := fmt.Sprintf("%s-lex-%s-%d", fixture.ID, word, i)
				mutatedFixture := fixture
				mutatedFixture.ID = varID
				mutatedFixture.Files = newFiles

				v := model.Variant{
					Fixture:  mutatedFixture,
					ParentID: fixture.ID,
					MutationChain: []model.Mutation{
						{
							ID:                  fmt.Sprintf("mut-lex-%s-%d", word, i),
							Type:                model.MutationLexical,
							Description:         fmt.Sprintf("Replaced '%s' with '%s'", word, sub),
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
	}

	return variants, nil
}
