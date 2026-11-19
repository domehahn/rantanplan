# Rantanplan CLI Reference

`rantanplan` is a Typer-based CLI for scanner assurance, differential benchmarking, adaptive evasion hunting, delta-debugging minimization and CI gating.

Run `uv run rantanplan --help` or `uv run rantanplan <command> --help` for the authoritative option list.

## Commands

| Command | Description |
| :--- | :--- |
| `doctor` | Check scanner installation, binary paths and version compatibility |
| `list [scanners\|cases\|capabilities]` | List registered scanners, clean-room test cases or canonical capabilities |
| `verify-ground-truth` | Validate all test cases against the independent ground-truth schema |
| `verify-ecosystem-cmd` | Run the end-to-end ecosystem verification suite |
| `inventory` | Discover and snapshot upstream capabilities of all scanners |
| `gaps` | Analyse capability matrix coverage gaps across scanners |
| `hunt --target T --mode false-negative\|false-positive --iterations N` | Hunt for evasions or false positives with adversarial mutators |
| `minimize --target T` | Delta-debug a test case down to minimal triggering content |
| `suite [offline-core\|static\|garak\|runtime]` | Execute a benchmark suite |
| `demo` | Zero-cost, network-independent demo matrix across all scanners |
| `benchmark` | Full benchmark and performance run |
| `gate --min-coverage N` | CI gate exit code based on verification criteria |
| `upstream check` | Upstream drift and compatibility monitoring |

## Binary discovery

For each scanner, the binary is resolved in this order: CLI override, `RANTANPLAN_<NAME>_BIN` environment variable, `PATH`. A scanner whose binary is missing is reported as not installed by `doctor`, and its runs end as `INCOMPLETE`.
