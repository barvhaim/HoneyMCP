.PHONY: help install dev test lint format clean run-dashboard run-example build inspector

help:
	@echo "Available commands:"
	@echo "  make install        - Install production dependencies"
	@echo "  make dev            - Install development dependencies"
	@echo "  make test           - Run tests"
	@echo "  make lint           - Run linting checks"
	@echo "  make format         - Format code"
	@echo "  make clean          - Clean build artifacts and cache"
	@echo "  make run-dashboard  - Run the Streamlit dashboard"
	@echo "  make run-example    - Run the demo server example"
	@echo "  make build          - Build the package"
	@echo "  make inspector      - Run MCP Inspector (npx)"

install:
	uv sync --no-dev

dev:
	uv sync

test:
	uv run pytest

lint:
	uv run black --check src/
	uv run pylint src/

format:
	uv run black src/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .pytest_cache/ .mypy_cache/ .ruff_cache/

run-dashboard:
	uv run streamlit run src/honeymcp/dashboard/app.py

run-example:
	uv run python examples/demo_server.py

build:
	uv build

inspector:
	npx @modelcontextprotocol/inspector
