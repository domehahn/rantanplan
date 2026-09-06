# Rantanplan Universal Scanner Assurance — Support Matrix

*Auto-generated support matrix detailing real target assurance capabilities, verification statuses, and sub-adapter integrations.*

---

## Ecosystem Target Assurance Summary

| Target Adapter Name | Category | Primary Interface / Command | Supported Capabilities | Ecosystem Support Status |
|---|---|---|---|---|
| `skil` | Artifact Scanner | `skil scan` | `secret.exfiltration`, `prompt.injection`, `code.execution` | `FULLY_SUPPORTED` |
| `skil-static` | Artifact Scanner | `skil scan --mode static` | `secret.exfiltration`, `command.injection`, `path.traversal` | `FULLY_SUPPORTED` |
| `skil-semantic` | Artifact Scanner | `skil scan --mode semantic` | `prompt.injection`, `jailbreak`, `social.engineering` | `FULLY_SUPPORTED` |
| `skil-validate` | Artifact Scanner | `skil validate` | `manifest.validation`, `format.integrity` | `FULLY_SUPPORTED` |
| `skil-lint` | Artifact Scanner | `skil lint` | `code.lint`, `security.best_practices` | `FULLY_SUPPORTED` |
| `skil-verify` | Evaluator | `skil verify` | `correctness.verification`, `safety.verification` | `FULLY_SUPPORTED` |
| `skil-eval` | Evaluator | `skil eval` | `quantitative.evaluation`, `benchmark.score` | `FULLY_SUPPORTED` |
| `skil-registry` | Governance | `skil registry check` | `registry.admission`, `policy.gate` | `FULLY_SUPPORTED` |
| `skil-policy` | Governance | `skil policy verify` | `policy.compliance`, `governance.enforcement` | `FULLY_SUPPORTED` |
| `skil-trust` | Governance | `skil trust check` | `publisher.trust`, `identity.verification` | `FULLY_SUPPORTED` |
| `skil-provenance` | Governance | `skil provenance verify` | `supply_chain.provenance`, `signature.verification` | `FULLY_SUPPORTED` |
| `skil-attestation` | Governance | `skil attestation verify` | `attestation.verification`, `cryptographic.claim` | `FULLY_SUPPORTED` |
| `skil-runtime-policy` | Governance | `skil runtime-policy verify` | `runtime.policy`, `execution.guard` | `FULLY_SUPPORTED` |
| `skillspector` | Artifact Scanner | `skillspector inspect` | `secret.exfiltration`, `prompt.injection`, `mcp.tool-poisoning` | `FULLY_SUPPORTED` |
| `garak-probe` | Probe Target | `garak --model_type test` | `llm.jailbreak`, `prompt.injection`, `llm.data-leakage` | `FULLY_SUPPORTED` |
| `garak-detector` | Detector Target | `garak --report_type detector` | `detector.eval`, `response.classification` | `FULLY_SUPPORTED` |
| `skillevaluator` | Evaluator | `skillevaluator eval` | `quality.structure`, `quality.redundancy`, `license.policy` | `FULLY_SUPPORTED` |
| `promptfoo-eval` | Evaluator | `promptfoo eval` | `prompt.evaluation`, `assertion.verification` | `FULLY_SUPPORTED` |
| `cisco` | Artifact Scanner | `cisco-ai-defense scan` | `secret.exfiltration`, `bytecode.malware`, `yara.signature` | `FULLY_SUPPORTED` |
| `tencent-skill` | Artifact Scanner | `tencent-ai-infra-guard scan-skill` | `secret.exfiltration`, `code.execution` | `FULLY_SUPPORTED` |
| `tencent-mcp` | Artifact Scanner | `tencent-ai-infra-guard scan-mcp` | `mcp.tool-poisoning`, `mcp.schema-confusion` | `FULLY_SUPPORTED` |
| `tencent-agent` | Runtime Scanner | `tencent-ai-infra-guard scan-agent` | `runtime.agent-hijack`, `memory.poisoning` | `FULLY_SUPPORTED` |
| `snyk-agent` | Artifact Scanner | `snyk code test` | `dependency.vulnerable`, `license.compliance` | `FULLY_SUPPORTED` |

---

## Profile Assurance & Fallback Policy

- **`mock` Profile**: Used during unit testing and zero-network local demonstrations.
- **`offline` Profile**: Executes real target binaries against local fixtures. Silent mock fallbacks are **strictly forbidden**; missing binaries return `ExecutionStatus.TARGET_UNAVAILABLE`.
- **`live` Profile**: Full dynamic evaluation against live models, endpoints, and scanners. Missing endpoints or binaries report `ExecutionStatus.TARGET_UNAVAILABLE`.
