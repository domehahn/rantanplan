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
| `test scanner --target T [--corpus DIR] [--seed N] [--mutants-per-case N] [--mutators a,b] [--format F] [--output FILE]` | Score one target (`dashboard`, `json`, `markdown`, `html`) |
| `compare --targets a,b [--format F]` | Score several targets on identical mutants |
| `mutate --case ID [--seed N]` | Show all mutants of a case with the oracle verdict |
| `hunt --target T --mode false-negative\|false-positive [--case ID] [--iterations N] [--seed N]` | Adaptive search with chained, oracle-checked mutations |
| `minimize --target T --case ID` | ddmin reproducer that keeps target outcome and label |
| `gate [--results FILE --min-grade B [--allow-low-confidence]] [--min-coverage N]` | CI gate (exit 1 on failure) |
| `export regression --target T [--output DIR]` | Export every evasion found as a regression case |
| `corpus build [--out DIR]` / `corpus list` | Regenerate / summarise the corpus |
| `suite offline-core` | Calibration check of the scoring scale (exit 1 if mis-ordered) |
| `benchmark [--output FILE]` | Regenerate `docs/REFERENCE_BENCHMARK.md` |
| `demo` | Legacy mock-profile matrix across all adapters (not a measurement of real scanners) |
| `upstream check` | Compare the two newest capability snapshots for drift |

All randomness derives from `--seed` (default `42151`).

## Binary discovery

For each scanner, the binary is resolved in this order: CLI override, `RANTANPLAN_<NAME>_BIN` environment variable, `PATH`. A scanner whose binary is missing is reported as not installed by `doctor`, and its runs end as `INCOMPLETE`.
