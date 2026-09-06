# Contributing to Rantanplan

We welcome contributions to Rantanplan! Whether adding clean-room test cases, implementing new scanner adapters, or improving differential reports, please follow these guidelines.

## 📋 Clean-Room Test Case Guidelines

1. **Independent Security Properties**: Every test case in `cases/` must represent an underlying security or quality property rather than copying competitor test suites verbatim.
2. **Paired Test Cases**: Create both a malicious/unsafe test case and a matching benign control case to exercise false-positive controls.
3. **Explicit Applicability Matrix**: Define which scanners are `required`, `optional`, or `not_applicable` based on their operational layer.

## 🛠️ Local Development Setup

```bash
# Install dependencies with uv
uv sync

# Run diagnostic check
make doctor

# Run test suite
make test

# Run offline demonstration
make demo
```
