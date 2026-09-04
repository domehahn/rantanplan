package model

import "time"

// MutationType identifies the category of transformation applied.
type MutationType string

const (
	MutationLexical         MutationType = "lexical"
	MutationSemantic        MutationType = "semantic"
	MutationSplit           MutationType = "split_instruction"
	MutationCrossFile       MutationType = "cross_file"
	MutationCodeAlias       MutationType = "code_alias"
	MutationEncoding        MutationType = "encoding"
	MutationUnicode         MutationType = "unicode"
	MutationNegativeContext MutationType = "negative_context"
	MutationCognitive       MutationType = "cognitive"
)

// Mutation represents a single transformation step applied to a fixture.
type Mutation struct {
	ID                  string       `json:"id"`
	Type                MutationType `json:"type"`
	Description         string       `json:"description"`
	PreservedProperties []string     `json:"preserved_properties"`
	Timestamp           time.Time    `json:"timestamp"`
	DiffSummary         string       `json:"diff_summary,omitempty"`
}

// Variant represents a mutated fixture derived from a parent fixture.
type Variant struct {
	Fixture       Fixture    `json:"fixture"`
	ParentID      string     `json:"parent_id"`
	MutationChain []Mutation `json:"mutation_chain"`
	Seed          int64      `json:"seed"`
	Depth         int        `json:"depth"`
}
