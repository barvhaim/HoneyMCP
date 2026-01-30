# Repository Guidelines

## Project Structure & Module Organization
- Source code lives in `src/honeymcp/` with core middleware in `src/honeymcp/core/` and data models in `src/honeymcp/models/`.
- LLM integration is in `src/honeymcp/llm/`, storage in `src/honeymcp/storage/`, and the Streamlit UI in `src/honeymcp/dashboard/`.
- Examples are in `examples/` (e.g., `examples/demo_server.py`).
- Tests are currently small and live at the repo root (e.g., `test_dynamic_tools.py`).
- Build artifacts and packaged outputs appear in `dist/`.

## Build, Test, and Development Commands
Use `uv` for local development:
- `uv sync` installs dev dependencies.
- `uv sync --no-dev` installs runtime-only dependencies.
- `uv run python examples/demo_server.py` runs the demo server.
- `streamlit run src/honeymcp/dashboard/app.py` launches the dashboard.
- `uv run pytest` runs tests.

Makefile shortcuts:
- `make lint` (ruff + mypy), `make format` (ruff format + fix), `make test`, `make build`.

## Coding Style & Naming Conventions
- Python 3.11+, 4-space indentation.
- Prefer explicit type hints and clear async boundaries for I/O.
- Formatting and linting are handled by Ruff (`make format`, `make lint`).
- Naming: modules and functions use `snake_case`, classes use `PascalCase`.

## Testing Guidelines
- Framework: `pytest` (see `pyproject.toml` dev deps).
- Run full suite with `uv run pytest` or `make test`.
- Name tests `test_*.py` and keep them close to related functionality when adding a `tests/` directory.

## Commit & Pull Request Guidelines
- Recent commits generally follow conventional prefixes like `feat:` and `docs:`, but history is mixed. Prefer `feat:`, `fix:`, `docs:`, `chore:` for new work.
- PRs should include a brief summary, testing performed, and links to related issues. Add screenshots for dashboard/UI changes.

## Security & Configuration Tips
- Store credentials in `.env` (do not commit). Example keys include `WATSONX_API_KEY` and `WATSONX_PROJECT_ID`.
- Config can be provided via `config.yaml`; event logs are written under `~/.honeymcp/events/`.
