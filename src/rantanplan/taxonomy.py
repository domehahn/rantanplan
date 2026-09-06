"""
Canonical taxonomy definitions for Rantanplan framework.
"""

CANONICAL_DOMAINS = [
    "artifact.integrity",
    "artifact.obfuscation",
    "prompt.injection",
    "prompt.leakage",
    "prompt.guardrail-bypass",
    "code.execution",
    "code.dynamic-loading",
    "secret.access",
    "secret.exfiltration",
    "network.outbound",
    "network.ssrf",
    "filesystem.read",
    "filesystem.write",
    "dependency.unpinned",
    "dependency.vulnerable",
    "dependency.typosquat",
    "dependency.source-redirection",
    "agent.hook",
    "agent.permission",
    "agent.delegation",
    "mcp.tool-poisoning",
    "mcp.surface-drift",
    "mcp.least-privilege",
    "memory.poisoning",
    "rag.poisoning",
    "multi-agent.toxic-flow",
    "quality.structure",
    "quality.redundancy",
    "pii.exposure",
    "license.policy",
    "runtime.policy-violation",
    "runtime.tool-abuse",
    "llm.jailbreak",
    "llm.hallucination",
    "llm.toxicity",
    "llm.data-leakage",
    "llm.misinformation",
]

RULE_MAPPINGS = {
    # SKIL Native Rules -> Canonical Domain
    "SKIL-TAINT-NETWORK": "secret.exfiltration",
    "SKIL-PROMPT-INJECT": "prompt.injection",
    "SKIL-SHELL-EXEC": "code.execution",
    "SKIL-UNICODE-BIDI": "artifact.obfuscation",
    "SKIL-HARD-NEGATIVE": "artifact.integrity",
    "SKIL-MCP-POISON": "mcp.tool-poisoning",
    "SKIL-DEEPEND-VULN": "dependency.vulnerable",
    
    # SkillSpector Rules -> Canonical Domain
    "SKILLSPECTOR-EXFIL": "secret.exfiltration",
    "SKILLSPECTOR-INJECT": "prompt.injection",
    "SKILLSPECTOR-CODE": "code.execution",
    
    # garak Probes -> Canonical Domain
    "garak.promptinject": "prompt.injection",
    "garak.dan": "llm.jailbreak",
    "garak.exfil": "secret.exfiltration",
}

