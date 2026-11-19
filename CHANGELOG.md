# Changelog

## Unreleased

### Fixed
- `test_skil_adapter_run` no longer fails when the `skil` binary is not installed. It is skipped, and a separate test asserts the adapter reports `INCOMPLETE` in that case.

### Fixed (doctor)
- `doctor` no longer reports missing binaries as installed. `discover_binary_version` returns a truthy `VERSION_UNKNOWN` sentinel, which all adapters mistook for a found binary. They now use `binary_exists()`.

### Changed
- Package version set to `0.1.0` (was `1.0.0`).
- `docs/CLI_REFERENCE.md` rewritten to match the actual CLI.
- README now describes the Python implementation (previously documented a Go build that does not exist in this repository).
- Bytecode (`__pycache__`) and generated `results/` are no longer tracked in git.
