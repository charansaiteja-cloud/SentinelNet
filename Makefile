.PHONY: install test lint type security check

install:
	python -m pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .
	ruff format --check .

type:
	mypy sentinel_net

security:
	bandit -q -r sentinel_net
	pip-audit --skip-editable

check: lint type test security
