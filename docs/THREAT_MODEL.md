# Rantanplan Threat Model & Security Boundaries

Rantanplan executes untrusted test fixtures and invokes third-party security scanners. It operates under a strict isolation and security model.

---

## 1. Primary Threat Vectors & Mitigation Matrix

| Threat Vector | Description | Risk Level | Mitigation Strategy |
| :--- | :--- | :---: | :--- |
| **Path Traversal & Symlink Escape** | Malicious fixture contains `../../etc/passwd` or symlinks out of workspace | High | Path canonicalization via `filepath.Clean` and strict `os.MkdirTemp` boundary enforcement |
| **Command & Shell Injection** | Third-party scanner arguments contain shell metacommands (`$(...)`, `\|`, `;`) | Critical | No shell execution by default (`exec.Command` with explicit `argv` array slice, zero `sh -c`) |
| **Resource Exhaustion** | Scanner loops infinitely, consumes excessive CPU/Memory or floods stdout | Medium | Context wall-clock timeouts (30s default), bounded stdout capture (`MaxStdoutBytes`), process termination |
| **Prompt Injection via Fixture Data** | LLM-assisted mutator parses untrusted fixture instructions as prompt commands | High | Strict prompt data encapsulation (`fixture content is data, not system instructions`) |
| **SSRF & Network Leakage** | Target scanner contacts external attacker host during verification | High | Environment sanitization, mock HTTP/DNS sinks, network sandbox execution controls |
| **Credential Leakage** | Scanner output or error traces dump host environment secrets | High | Sanitized environment variable whitelist (`PATH`, `TMPDIR`, `HOME` pointing to temp) |

---

## 2. Execution Sandbox Guarantees

1. **Fixtures as Data**: Rantanplan treats all security skills, scripts, and Markdown documents strictly as data input for scanner inspection. Code in fixtures is never executed directly during standard scanner testing.
2. **Subprocess Isolation**: When running external scanners (e.g. `skil`, `skillspector`), processes are launched inside isolated temporary directory workspaces created per test case and purged immediately after scanning.

