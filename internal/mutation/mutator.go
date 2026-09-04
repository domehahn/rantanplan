package mutation

import (
	"context"
	"fmt"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// Mutator interface defines the contract for mutation generators.
type Mutator interface {
	Name() string
	Type() model.MutationType
	Mutate(ctx context.Context, fixture model.Fixture, seed int64) ([]model.Variant, error)
}

// Engine manages registered mutators, mutation budgets, and generation limits.
type Engine struct {
	mutators []Mutator
}

func NewEngine() *Engine {
	return &Engine{
		mutators: make([]Mutator, 0),
	}
}

func (e *Engine) Register(m Mutator) {
	e.mutators = append(e.mutators, m)
}

// MutateFixture applies mutators up to maxDepth and maxVariants limits.
func (e *Engine) MutateFixture(ctx context.Context, seed model.Fixture, maxVariants int, seedNum int64) ([]model.Variant, error) {
	var variants []model.Variant

	for _, m := range e.mutators {
		if len(variants) >= maxVariants {
			break
		}

		mutVariants, err := m.Mutate(ctx, seed, seedNum)
		if err != nil {
			return nil, fmt.Errorf("mutator %s failed: %w", m.Name(), err)
		}

		for _, v := range mutVariants {
			variants = append(variants, v)
			if len(variants) >= maxVariants {
				break
			}
		}
	}

	return variants, nil
}
