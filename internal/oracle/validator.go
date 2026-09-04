package oracle

import (
	"fmt"
	"strings"

	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// InvariantValidator checks whether a mutation maintains ground-truth invariants.
type InvariantValidator struct{}

func NewInvariantValidator() *InvariantValidator {
	return &InvariantValidator{}
}

// ValidatePreservation verifies if a variant retains the original ground-truth security property.
func (v *InvariantValidator) ValidatePreservation(original model.Fixture, variant model.Variant) (bool, string) {
	if !original.GroundTruth.Vulnerable {
		// Benign fixtures remain benign
		return true, "benign fixture preserved"
	}

	content := strings.ToLower(variant.Fixture.MainContent())
	for _, file := range variant.Fixture.Files {
		content += "\n" + strings.ToLower(file.Content)
	}

	// Check if defensive negation was accidentally introduced in a vulnerable variant
	if strings.Contains(content, "never send") || strings.Contains(content, "do not execute") || strings.Contains(content, "must never be used") {
		if variant.Fixture.GroundTruth.Vulnerable {
			return false, "mutation introduced defensive negation; ground truth invalidated"
		}
	}

	// Verify capability sources & sinks for exfiltration
	hasSource := false
	for _, src := range []string{"secret", "credential", "authentication", "api key", "os.environ", "access material", "authorization"} {
		if strings.Contains(content, src) {
			hasSource = true
			break
		}
	}

	hasSink := false
	for _, sink := range []string{"send", "upload", "transmit", "forward", "post", "endpoint", "attacker.example.com", "remote", "http"} {
		if strings.Contains(content, sink) {
			hasSink = true
			break
		}
	}

	if original.GroundTruth.Category == "data-exfiltration" {
		if !hasSource || !hasSink {
			return false, fmt.Sprintf("lost capability invariants: source=%v, sink=%v", hasSource, hasSink)
		}
	}

	return true, "invariants verified"
}
