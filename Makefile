.PHONY: install lint typecheck test cov doctor corpus calibrate benchmark check demo clean

install:
	uv sync --extra dev

lint:
	uv run ruff check .

typecheck:
	uv run mypy src/rantanplan

test:
	uv run pytest -q

cov:
	uv run pytest -q --cov=rantanplan --cov-report=term-missing --cov-fail-under=90

doctor:
	uv run rantanplan doctor

corpus:
	uv run rantanplan corpus build --out corpus
	uv run rantanplan verify-ground-truth

calibrate:
	uv run rantanplan suite offline-core

benchmark:
	uv run rantanplan benchmark

# Everything CI runs
check: lint typecheck cov corpus calibrate benchmark
	git diff --exit-code -- corpus docs/REFERENCE_BENCHMARK.md

demo:
	uv run rantanplan compare

clean:
	rm -rf dist/ *.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage results/ snapshots/ regression_bundles/
