.PHONY: setup data test lint fmt check

setup:            ## create the venv and install everything for development
	uv venv --python 3.12
	uv pip install -e ".[dev,ui]"

data:             ## regenerate the synthetic store (deterministic)
	.venv/bin/python -m redline.store.generate

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check src tests

fmt:
	.venv/bin/ruff check --fix src tests
	.venv/bin/ruff format src tests

check: lint test  ## what CI runs
