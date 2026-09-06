# Rantanplan Differential Capability Matrix

This matrix documents the functional security and quality coverage claimed and verified across all four target scanners.

| Canonical Domain | SKIL | SkillSpector | garak | SkillEvaluator | Rantanplan Test Cases |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Artifact Integrity** | ● | ● | — | ◐ | `static-defensive-negation-001` |
| **Artifact Obfuscation** | ● | ● | — | ◐ | `unicode-bidi-obfuscation-001` |
| **Prompt Injection** | ● | ● | ● | ◐ | `prompt-injection-override-001` |
| **Secret Exfiltration** | ● | ● | — | ◐ | `static-secret-to-network-001` |
| **MCP Tool Poisoning** | ● | ● | — | — | `mcp-tool-poisoning-001` |
| **LLM Red-Team / Jailbreak** | ◐ | — | ● | ◐ | `llm-jailbreak-001` |
| **Skill Quality & Structure** | ● | ◐ | — | ● | `quality-structure-001` |
| **Skill Deduplication** | ● | — | — | ● | `dedup-semantic-001` |
| **Attestation & Provenance** | ● | — | — | — | `attestation-closure-001` |
| **Runtime Enforcement** | ● | — | — | — | `runtime-policy-enforce-001` |

### Key
- `●` Full Native Capability
- `◐` Partial or Delegated Capability
- `—` Not Applicable / Unsupported at this Operational Layer

