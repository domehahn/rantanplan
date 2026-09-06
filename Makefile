.PHONY: install lint test doctor inventory offline static garak runtime full report gaps benchmark demo clean

install:
	uv sync

lint:
	uv run ruff check .
	uv run mypy src/rantanplan

test:
	uv run pytest -v

doctor:
	uv run rantanplan doctor

inventory:
	uv run rantanplan inventory

offline:
	uv run rantanplan suite offline-core

static:
	uv run rantanplan suite static

garak:
	uv run rantanplan suite garak

runtime:
	uv run rantanplan suite runtime

full:
	uv run rantanplan run-all

report:
	uv run rantanplan report default

gaps:
	uv run rantanplan gaps

benchmark:
	uv run rantanplan benchmark

demo:
	uv run rantanplan demo

clean:
	rm -rf bin/ dist/ *.egg-info .pytest_cache .coverage results/ snapshots/
