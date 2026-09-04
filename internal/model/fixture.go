package model

// FixtureFile represents an individual file attached to a fixture bundle.
type FixtureFile struct {
	Path    string `json:"path" yaml:"path"`       // Relative path within fixture directory (e.g., SKILL.md)
	Content string `json:"content" yaml:"content"` // Text or binary code content
}

// Fixture represents a complete security test case with ground truth and file tree.
type Fixture struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Category    string            `json:"category" yaml:"category"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	GroundTruth GroundTruth       `json:"ground_truth" yaml:"ground_truth"`
	Files       []FixtureFile     `json:"files" yaml:"files"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	ParentID    string            `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`
	Seed        int64             `json:"seed,omitempty" yaml:"seed,omitempty"`
}

// MainContent returns the primary file content (e.g., SKILL.md or primary entrypoint).
func (f *Fixture) MainContent() string {
	for _, file := range f.Files {
		if file.Path == "SKILL.md" || file.Path == "main.py" || file.Path == "index.js" {
			return file.Content
		}
	}
	if len(f.Files) > 0 {
		return f.Files[0].Content
	}
	return ""
}
