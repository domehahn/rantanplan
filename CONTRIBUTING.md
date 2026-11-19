# Contributing to Rantanplan

Thanks for helping. The most valuable contributions are **new corpus cases**, **verified scanner adapters**
and **mutators or oracle checks that expose a real weakness**.

## Setup

```bash
git clone https://github.com/domehahn/rantanplan.git && cd rantanplan
make install      # uv sync --extra dev
make check        # lint, tests with coverage gate, corpus + benchmark freshness, calibration
```

## Ground rules

* **Tests and lint must pass** (`make check`). Coverage gate is 90%.
* **The corpus is generated.** Edit `src/rantanplan/corpus_builder.py`, then run `make corpus` and commit the
  regenerated `corpus/`. CI fails if `corpus/` is stale. `docs/REFERENCE_BENCHMARK.md` is generated too (`make benchmark`).
* **Label independence.** A case's `malicious` label is written by you, not copied from a scanner's output.
  Add benign counterparts (hard negatives) for every attack shape. `rantanplan verify-ground-truth` checks
  labels against the reference semantics and must pass.
* **Clean-room.** Do not copy another project's test suite verbatim. Use dummy credentials only.
* **Mutators** must stay deterministic given `(seed, case, mutator)` and may never edit protected spans (hosts, URLs,
  commands). The oracle decides validity; add a test for each new rejection or acceptance rule.
* **Adapters** must return `INCOMPLETE`, never a detection or a pass, when a scanner crashes, times out or prints
  something unparsable (`tests/test_adapter_contract.py` enforces this). New adapters should include a recorded
  real output under `tests/fixtures/` and say which version produced it.
* **No invisible characters in source.** Write Unicode tricks as escapes (`"​"`); `ruff` enforces this.

## Reporting results

If you score a real scanner, add the Markdown report under `docs/benchmarks/` with the scanner version, commit,
seed, and a note on how to read the misses. See `docs/benchmarks/skil-v0.6.0.md`.

## Pull requests

Keep PRs focused, update `CHANGELOG.md`, and describe what you verified. By contributing you agree to license your
work under the MIT License. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
