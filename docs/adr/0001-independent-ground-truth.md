# ADR 0001: Independent Ground Truth Model

## Status
Accepted

## Context
Existing AI security scanners (e.g. SKIL, SkillSpector, garak, promptfoo) evaluate skills or models against their own internal rule definitions. Using any external scanner as the ground truth creates a circular dependency (`Scanner detection != Ground truth`).

## Decision
Rantanplan implements an **Independent Ground Truth Model**. Ground truth is defined separately in YAML/JSON fixture schemas specifying:
- Ground-truth vulnerability status (`vulnerable: true/false`)
- Required severity thresholds
- Capability sources and sinks (e.g. `secrets.read` + `network.external`)
- Required semantic invariants

No external security tool or scanner is ever used as the ground truth.

## Consequences
- Prevents vendor lock-in or circular bias.
- Guarantees vendor-neutral assessment.

