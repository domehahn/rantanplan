# Rantanplan Security Policy & Safety Boundaries

Rantanplan is an open-source defensive scanner test framework designed to test, benchmark, and stress-test AI agent security controls, static analyzers, and evaluators.

## 🛡️ Defensive Safety Boundaries

To prevent accidental host damage or unintended offensive side effects during scanner testing, Rantanplan enforces strict safety constraints:

1. **Fixtures are Inert Data Input**:
   - Potentially dangerous instructions (e.g. `rm -rf /`, `requests.post(url, json=os.environ)`) exist strictly as static text data inside fixture files.
   - Rantanplan **NEVER** executes fixture commands in a shell or passes fixture strings to system interpreters.

2. **No Real Credentials**:
   - Only canary tokens, dummy API keys (`sk-proj-0000...`, `AKIAIOSFODNN7EXAMPLE`), and fake hashes are used in test fixtures.
   - Real system environment secrets are sanitized and stripped before calling scanner subprocesses.

3. **Subprocess Isolation**:
   - Scanner binaries (SKIL, SkillSpector, garak, SkillEvaluator) are executed via explicit `argv` slices without shell wrapper execution (`shell=False`).
   - Execution is constrained by wall-clock timeouts, memory limits, and isolated temporary `HOME` directories.

4. **Network Isolation**:
   - Core test suites (`offline-core`, `static`, `demo`) operate with zero public network dependencies.
   - Mock services (Mock LLM, Mock MCP, Mock HTTP Sink) bind strictly to `127.0.0.1` loopback endpoints.
   - Rantanplan never contacts real cloud metadata endpoints (`169.254.169.254`), Kubernetes APIs, or production cloud infrastructure.
