# Repository Guidelines

## Project Structure & Module Organization
- Source lives in `src/honeymcp/`. Core middleware in `src/honeymcp/core/` (`middleware.py`, `ghost_tools.py`, `dynamic_ghost_tools.py`, `fingerprinter.py`, `tool_creator.py`, `catalog_updater.py`); Pydantic models in `src/honeymcp/models/`.
- LLM integration in `src/honeymcp/llm/` (`clients/`, `analyzers.py`, `prompts/`); session/event storage in `src/honeymcp/storage/` (pluggable `memory`/`redis`/`sqlite` session backends + JSON `event_store.py`).
- Additional subsystems: `analysis/` (pattern detection), `adaptive/` (attacker profiling + catalog optimization), `forensics/` (replay, reports, exporters), `integrations/` (Slack, notifiers, SSE streaming, alerting), `api/` (FastAPI service), `dashboard/react_umd/` (React UMD bundle served by the API).
- Examples are in `examples/` (e.g., `examples/demo_server.py`).
- Tests live in `tests/` as `test_*.py` (full suite: middleware, protection modes, dynamic tools, session backends, forensics, API, E2E). A few loose `test_*.py` scripts also sit at the repo root — the maintained suite is `tests/`.
- Build artifacts and packaged outputs appear in `dist/`.

## Build, Test, and Development Commands
Use `uv` for local development:
- `uv sync` installs dev dependencies; `uv sync --no-dev` installs runtime-only.
- `uv run python examples/demo_server.py` runs the demo server (`MCP_TRANSPORT` selects stdio/http/sse).
- `make run-ui` launches the FastAPI dashboard at `http://127.0.0.1:8001/dashboard`.
- `uv run pytest` (or `make test`) runs tests; `uv run pytest tests/test_dynamic_tools.py::test_name` runs one.

Makefile shortcuts:
- `make lint` runs **black --check + pylint**; `make format` runs **black**. (Ruff is a configured dev dependency but the Makefile targets use black/pylint.)
- `make test`, `make build`, `make inspector`.

## Coding Style & Naming Conventions
- Python 3.11+, 4-space indentation.
- Prefer explicit type hints (`Optional[T]`, `Union[A, B]`) and clear async boundaries for I/O.
- Formatting via black, linting via pylint (see `make format` / `make lint`).
- Naming: modules and functions use `snake_case`, classes use `PascalCase`.

## Testing Guidelines
- Framework: `pytest` (`pytest-asyncio` for async tests); see `pyproject.toml` dev deps.
- Run the full suite with `uv run pytest` or `make test`; `uv run pytest --cov=honeymcp` for coverage.
- Name tests `test_*.py` and place them under `tests/`. Mock LLM calls for deterministic runs.

## Commit & Pull Request Guidelines
- Recent commits generally follow conventional prefixes like `feat:` and `docs:`, but history is mixed. Prefer `feat:`, `fix:`, `docs:`, `chore:` for new work.
- PRs should include a brief summary, testing performed, and links to related issues. Add screenshots for dashboard/UI changes.

## Security & Configuration Tips
- Store credentials in `.env.honeymcp` (loaded first, falls back to `.env`); do not commit them. Keys depend on `LLM_PROVIDER` (`watsonx`/`openai`/`rits`) — e.g. `WATSONX_API_KEY`, `WATSONX_PROJECT_ID`, `OPENAI_API_KEY`, `RITS_API_KEY`. Note the `.env.example` vs client env-var naming mismatch documented in `CLAUDE.md`.
- Config is provided via `honeymcp.yaml` (search order: `./honeymcp.yaml` → `~/.honeymcp/honeymcp.yaml` → defaults); scaffold with `honeymcp init`. Event logs are written under `~/.honeymcp/events/` (override with `HONEYMCP_EVENT_PATH`) and contain sensitive attack data.
