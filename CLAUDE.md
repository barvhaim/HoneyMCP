# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**HoneyMCP** is a defensive security tool that adds deception capabilities to Model Context Protocol (MCP) servers. It detects malicious AI agents attempting data exfiltration and indirect prompt injection attacks by injecting "ghost tools" (honeypots) that capture attack context when triggered.

**Technology Stack:**
- Python 3.11+
- FastMCP 3.0+ (MCP server framework, wraps `mcp>=1.25`)
- LangChain LLM clients (`langchain-openai`, `langchain-ibm`) — LiteLLM is also a dependency
- Pydantic 2.10+ (data models and validation)
- FastAPI + Uvicorn + a React UMD bundle (`dashboard/react_umd/`) for the real-time attack dashboard
- PyYAML (configuration)

## Development Commands

Use `uv` for everything (`make` targets wrap `uv run`).

```bash
uv sync                 # install dev dependencies
uv sync --no-dev        # runtime-only

make test               # uv run pytest
uv run pytest tests/test_dynamic_tools.py       # single file
uv run pytest tests/test_middleware_dispatch.py::test_name  # single test
uv run pytest --cov=honeymcp                    # with coverage

make format             # black src/
make lint               # black --check src/ + pylint src/
uv run ruff check src/  # ruff is a dev dep but NOT wired into make targets or CI

make run-example        # uv run python examples/demo_server.py
make run-ui             # dashboard at http://127.0.0.1:8001/dashboard
make inspector          # npx @modelcontextprotocol/inspector
make build              # uv build
```

> Note: `AGENTS.md` claims `make lint`/`make format` use ruff+mypy — that is stale. The Makefile uses **black + pylint**. When the two docs disagree, trust the Makefile and `pyproject.toml`.

CI (`.github/workflows/ci.yml`) runs `make lint` plus `uv run pytest` on Python 3.11/3.12/3.13, and installs with `uv sync --locked` — so **commit `uv.lock` changes** or CI fails at install. `pylint` is scored, not pass/fail: `fail-under = 7.0` (`pyproject.toml`). Black uses `line-length = 100`.

### Running the Demo Server

Transport is selected by the `MCP_TRANSPORT` env var (see `.env.example`, default there is `sse`):

```bash
uv run python examples/demo_server.py               # stdio (Claude Desktop)
MCP_TRANSPORT=http uv run python examples/demo_server.py
MCP_TRANSPORT=sse  uv run python examples/demo_server.py   # MCP Inspector
```

Example servers: `demo_server.py` (static+dynamic), `demo_server_dynamic.py`, `banking_server.py`, and the `demo_video_before/after.py` pair.

### CLI (`honeymcp` entry point)

Defined in `cli.py`, registered as the `honeymcp` script:
- `honeymcp init [-d DIR] [-f]` — scaffold `honeymcp.yaml` + `.env.example`
- `honeymcp version`
- `honeymcp clean-data [--path] [--config] [-y]` — delete stored event JSON

`cli_tool_creator.py` (`create_tool_command`) drives the LLM `ToolCreatorAgent` to author new honeypot tools, but is **not** wired into the `honeymcp` CLI — it is invoked as a module/script.

## Architecture Overview

### Core request flow

```
AI Agent (Claude, etc.)
    ↓ MCP Protocol
HoneyMCP-wrapped FastMCP server
    └─ intercepting_call_tool()  (core/middleware.py)
        0. run_middleware is False?     → re-entrant call, delegate WITHOUT recording
        1. Resolve/track session (storage/session_backend.py) & record_tool_call()
        2. Allowlist bypass?            → run real tool
        3. Rate limit exceeded?         → throttle (sleep 2s) / block (error)
        4. is_attacker(session)?        → apply protection mode (SCANNER/COGNITIVE)
        5. Is this a ghost tool?        → fingerprint_attack() + store event + mark attacker
                                          + optional Slack webhook
        6. Otherwise                    → execute real tool normally
         ↓
Event Storage (~/.honeymcp/events/YYYY-MM-DD/evt_*.json)
    ├─ FastAPI service (api/app.py) → React dashboard at /dashboard
    ├─ Pattern detection / attacker profiling (analysis/, adaptive/)
    ├─ Forensic reports & exports (forensics/)
    └─ Alerting: Slack / webhooks / SSE stream (integrations/)
```

### Critical components

**1. Middleware (`core/middleware.py`)** — the heart of the system.
- `honeypot(server, ...)`: main entry. Long keyword-arg signature covering ghost tools, dynamic-tool generation, protection mode, session backend, rate limiting, allowlist, event retention. Registers ghost tools and monkey-patches the server's tool dispatch.
- `honeypot_from_config(server, config_path=None)`: loads `HoneyMCPConfig` and forwards every field to `honeypot()`.
- `intercepting_call_tool()`: the interceptor implementing the flow above.
- `_register_ghost_tool()` / `_register_dynamic_ghost_tool()`: register honeypots as real `@server.tool()`s. Dynamic tools are registered by building a handler from an LLM-generated signature string — the generated output is sanitized (see commit history: "harden dynamic ghost tool generation").

Three subtleties that bite when editing this file:
- **Re-entry guard.** FastMCP 3.0's middleware chain calls `self.call_tool(..., run_middleware=False)` via `call_next`, re-entering the interceptor a second time. The guard at the top delegates immediately on `run_middleware is False`. Removing it double-records every tool call and corrupts `tool_call_sequence`. Any new bookkeeping must go *after* this guard.
- **Two dispatch-patching paths.** If the server has a `call_tool` attribute it is replaced outright; otherwise `_patch_tool_access()` is used, with `_call_tool_directly()` as the fallback executor when no `original_call_tool` was captured. Changes to interception must work on both paths.
- **Backend-dependent attacker marking.** For `InMemorySessionBackend` the code calls the *sync* `mark_attacker_detected()` from `fingerprinter.py`; every other backend uses `await session_backend.mark_attacker()`. The two stores are not interchangeable — keep both branches in sync.

Returns are `ToolResult` objects (`meta={"is_error": True}` for the error paths), not bare strings.

**2. Ghost tools**
- Static: `core/ghost_tools.py` → `GHOST_TOOL_CATALOG` (dict of `GhostToolSpec`). `get_ghost_tool()` / `list_ghost_tools()` accessors.
- Dynamic: `core/dynamic_ghost_tools.py` → `DynamicGhostToolGenerator`, pre-generated at startup (not per-request) and cached (`cache_ttl`, default 3600s).
- `core/tool_creator.py` (`ToolCreatorAgent`) + `core/catalog_updater.py` (`CatalogUpdater`) can synthesize new honeypots and write them back into `ghost_tools.py`/`middleware.py`.

**3. Attack detection (`core/fingerprinter.py`)**
- `fingerprint_attack()`, `record_tool_call()`, `mark_attacker_detected()`, `is_attacker_detected()`. All session-scoped.

**4. Session state (`storage/`)** — pluggable backends behind `session_backend.py` (`SessionBackend` ABC): `memory_backend.py`, `redis_backend.py`, `sqlite_backend.py`. Chosen via `session_backend_type` config. `session_store.py`-style logic lives here; event persistence is `event_store.py` (JSON on disk).

**5. Analysis & adaptive loop**
- `analysis/pattern_detector.py`: correlates events into `AttackPattern`s.
- `adaptive/`: `attacker_profiler.py` (builds `AttackerProfile`s), `effectiveness_tracker.py`, `catalog_optimizer.py` — feedback loop that scores ghost-tool effectiveness and recommends catalog changes.

**6. Forensics (`forensics/`)** — `replay_engine.py` (`AttackTimeline`, step replay), `report_generator.py` (`ForensicReport`, `ComparisonReport`), `exporters.py` (multi-format export).

**7. Integrations (`integrations/`)** — `alerting.py` (rules engine), `notifiers.py` (multi-channel delivery + retry), `slack.py` (webhook), `streaming.py` (SSE for the dashboard's `/stream`).

**8. API service (`api/app.py`)** — `create_app(config_path=None)` builds a FastAPI app that serves the React dashboard (`dashboard/react_umd/`, a UMD bundle — no JS build step) and exposes ~35 routes. This is what `make run-ui` launches (`honeymcp.api.app:app`). It's the single largest module in the repo; route groups:
- Core: `/health`, `/dashboard`, `/events` (GET + DELETE), `/events/{id}`, `/metrics`, `/filters`, `/stream` (SSE)
- Analysis: `/patterns`, `/patterns/summary`, `/profiles`, `/profiles/{session_id}`
- Forensics: `/replay/*` (start, control, state, active), `/reports/generate`, `/reports/compare`, `/export/timeline/{session_id}`, `/export/report/{report_id}`
- Adaptive loop: `/adaptive/*` (metrics, top-tools, recommendations, snapshots, profiles, campaigns, hints, compare-profiles)

**9. LLM integration (`llm/`)**
- `llm/clients/__init__.py`: `get_chat_llm_client(...)` selects a provider from the `LLM_PROVIDER` env var. Provider enum in `llm/clients/provider_type.py`: **`watsonx`, `openai`, `rits`** (RITS = an OpenAI-compatible endpoint). There is no standalone `llm_client_watsonx.py`.
- `llm/analyzers.py`: `extract_tool_info()` / `analyze_server_context()` pull tool metadata off a FastMCP server.
- `llm/prompts/` (a package): prompt templates for server analysis and ghost-tool generation.

## Protection Modes (`models/protection_mode.py`)

**SCANNER (default)** — after a ghost tool triggers, all subsequent tool calls in that session return errors. Fast lockout for automated scanners.

**COGNITIVE** — after trigger, the session keeps working but real tools return LLM-generated fake/mock data, keeping a sophisticated attacker engaged for intelligence gathering. Enforced in `intercepting_call_tool()` by branching on `config.protection_mode`.

Detection is **session-scoped**: one session tripping a honeypot does not affect other sessions.

## Configuration

Resolution order (`HoneyMCPConfig.load`): explicit path → `./honeymcp.yaml` → `~/.honeymcp/honeymcp.yaml` → defaults. The YAML is *sectioned* (`dynamic_tools`, `alerting`, `storage`, `dashboard`, `sessions`, `rate_limit`, `allowlist`, `session_backend`) and flattened into the flat `HoneyMCPConfig` fields by `_from_yaml_dict` — when adding a config field, update both the flat field **and** the section mapping. See `honeymcp.yaml` for the canonical layout.

Key fields beyond the basics: `session_ttl`, `max_sessions`, `max_age_days` (event auto-cleanup), `rate_limit_max_calls_per_minute` + `rate_limit_action` (`throttle`|`block`), `allowlist_session_ids`, `session_backend_type` (+ `redis_url` / `sqlite_path`).

Event storage path override: `HONEYMCP_EVENT_PATH` env var (see `resolve_event_storage_path`).

### Environment variables

HoneyMCP loads `.env.honeymcp` first, then falls back to `.env` (see `llm/clients/__init__.py`) — this keeps honeypot LLM credentials out of the host project's env.

```bash
LLM_PROVIDER=rits            # watsonx | openai | rits
LLM_MODEL=openai/gpt-oss-120b

OPENAI_API_KEY=

# watsonx.ai — use THESE names; see the mismatch warning below
WATSONX_API_ENDPOINT=...
WATSONX_API_KEY=...
WATSONX_PROJECT_ID=...

# RITS (OpenAI-compatible)
RITS_API_KEY=
RITS_API_BASE_URL=http://.../   # without /v1 suffix

MCP_TRANSPORT=sse            # stdio | http | sse
```

> **watsonx env-var names are load-bearing.** `llm/clients/__init__.py` reads `WATSONX_API_ENDPOINT` / `WATSONX_API_KEY` / `WATSONX_PROJECT_ID` with **no fallbacks**. An older naming (`WATSONX_URL` / `WATSONX_APIKEY`) was used across `.env.example`, `cli.py`'s init template, and the READMEs; all were corrected to match the client. If you reintroduce the old names, watsonx silently gets `url=None, apikey=None` — and since `fallback_to_static=True` swallows the auth failure, the only symptom is "dynamic tools never generate."

### Programmatic

```python
from honeymcp import honeypot, ProtectionMode

mcp = honeypot(
    mcp,
    ghost_tools=["list_cloud_secrets", "execute_shell_command"],
    use_dynamic_tools=True,
    num_dynamic_tools=3,
    fallback_to_static=True,
    protection_mode=ProtectionMode.SCANNER,   # or COGNITIVE
    session_backend_type="memory",            # memory | redis | sqlite
    rate_limit_max_calls_per_minute=None,
)
```

Public API (`honeymcp/__init__.py`): `honeypot`, `honeypot_from_config`, `AttackFingerprint`, `GhostToolSpec`, `HoneyMCPConfig`, `ProtectionMode`.

## Common Development Tasks

**Add a static ghost tool:** add a `GhostToolSpec` to `GHOST_TOOL_CATALOG` (`core/ghost_tools.py`) with a fake-response generator, add its handler branch in `_register_ghost_tool()` (`core/middleware.py`), update `README.md`. (`tests/test_new_honeypot_tools.py` covers this path.)

**Change dynamic generation:** edit templates in `llm/prompts/`, adjust `DynamicGhostToolGenerator` in `core/dynamic_ghost_tools.py`, verify with a demo server and `tests/test_dynamic_tools.py` / `test_dynamic_tool_registration.py`.

**Add a protection mode:** add enum value in `models/protection_mode.py`, branch in `intercepting_call_tool()`, thread through `HoneyMCPConfig` (flat field + `_from_yaml_dict`), cover in `tests/test_protection_modes.py`.

**Add an LLM provider:** add to `LLMProviderType`, wire it in `llm/clients/__init__.py` (`_get_base_llm_settings` + `get_chat_llm_client`), add env vars to `.env.example`.

**Add a session backend:** subclass `SessionBackend` in `storage/`, register it where `session_backend_type` is resolved, cover in `tests/test_session_backends.py`.

## Conventions

- **Async I/O everywhere** — including the interceptor: `intercepting_call_tool` is `async def` and awaits session-backend reads, fingerprinting, event storage, and webhook delivery on the hot path. Ghost-tool `response_generator` callables are the exception: those are sync.
- Comprehensive type hints; `Optional[T]` / `Union[A, B]`.
- `logger = logging.getLogger(__name__)`; INFO normal / WARNING fallback / ERROR failure.
- Catch specific exceptions; **fall back gracefully** (dynamic tools → static tools when `fallback_to_static=True` and LLM generation fails is the canonical example).
- HoneyMCP is **detection, not prevention** (defense in depth). Ghost tools must never be reachable by legitimate users — zero false positives is a design invariant. Treat `~/.honeymcp/events/` as sensitive attack data.

## Testing

Tests live in `tests/` (`test_*.py`), covering middleware dispatch, protection modes, dynamic tool generation/registration, session backends, rate limiting, allowlist, event storage/cleanup, pattern detection, forensics, alerting/streaming, the FastAPI app, and full E2E demo-server attack scenarios (`test_demo_server_e2e.py`, `test_demo_server_dynamic_e2e.py`). LLM calls are mocked for determinism. Note: a few loose `test_*.py` scripts also exist at the repo root — the maintained suite is under `tests/`.

## Troubleshooting

- **Dynamic tools not generating:** check `.env.honeymcp`/`.env` LLM credentials for the active `LLM_PROVIDER`, watch for the watsonx env-var naming mismatch above, enable `logging.basicConfig(level=logging.DEBUG)`, confirm `fallback_to_static=True`.
- **Events not stored:** check write perms on the resolved event path (`HONEYMCP_EVENT_PATH` may override), look for async write errors in logs.
- **Ghost tools not triggering:** confirm they registered (inspect the server's tool list), names are case-sensitive, review session tracking and `is_attacker_detected()`.
- **Dashboard empty:** confirm events exist under `~/.honeymcp/events/YYYY-MM-DD/`, that `make run-ui` points at the same event path, and hit `/health` and `/events` directly to isolate API vs. UI.

## Further reading

`docs/` holds deeper per-subsystem docs — `architecture.md`, `adaptive-ghost-tools.md`, `forensics-and-replay.md`, `pattern-analysis.md`, `session-backends.md`, `streaming-and-alerting.md`, `cli-reference.md`, `development.md`, `security-considerations.md`, `use-cases.md`, `faq.md`. Consult these before reverse-engineering a subsystem from source.
