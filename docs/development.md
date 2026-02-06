## 🛠️ Development

### Install from Source

```bash
git clone https://github.com/barvhaim/HoneyMCP.git
cd HoneyMCP
uv sync

# Run tests
uv run pytest

# Lint & format
make lint
make format
```

### Project Structure

```
HoneyMCP/
├── src/honeymcp/
│   ├── __init__.py              # Main exports
│   ├── cli.py                   # CLI (honeymcp init, version)
│   ├── core/
│   │   ├── middleware.py        # @honeypot decorator
│   │   ├── ghost_tools.py       # Ghost tool catalog
│   │   ├── fingerprinter.py     # Attack context capture
│   │   └── dynamic_ghost_tools.py# LLM-driven ghost tool generation
│   ├── models/
│   │   ├── events.py            # AttackFingerprint model
│   │   ├── ghost_tool_spec.py   # GhostToolSpec definition
│   │   └── config.py            # Configuration
│   ├── llm/
│   │   ├── analyzers.py          # Tool extraction and categorization
│   │   ├── clients/              # LLM providers (Watsonx/OpenAI/RITS)
│   │   └── prompts/              # Prompt templates
│   ├── integrations/            # External integrations
│   ├── storage/
│   │   └── event_store.py       # JSON event persistence
│   └── dashboard/
│       └── react_umd/           # React dashboard assets
├── examples/
│   ├── demo_server.py           # Static ghost tools demo
│   └── demo_server_dynamic.py   # Dynamic ghost tools demo
├── tests/                       # Pytest suite (e2e + dynamic tools)
├── pyproject.toml               # Dependencies
└── README.md                    # This file
```

### Tests

```bash
uv run pytest
```

Notes:
- Dynamic tool tests require LLM credentials in `.env.honeymcp` and will skip if env vars are missing.
