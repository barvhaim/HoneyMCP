# 🍯 HoneyMCP

<img src="images/logo.png" alt="HoneyMCP logo" width="300" height="300" />

**Detect AI Agent Attacks Through Deception**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

HoneyMCP is a defensive security tool that adds deception capabilities to Model Context Protocol (MCP) servers. It injects "ghost tools" (fake security-sensitive tools) that act as honeypots, detecting two critical threat categories:

- **Data Exfiltration** (via "get" tools) - Detects attempts to steal sensitive data like credentials, secrets, or private files
- **Indirect Prompt Injection** (via "set" tools) - Detects injection of malicious instructions that could manipulate AI agents working in this environment

**One line of code. High-fidelity detection. Complete attack telemetry.**

---

## Why HoneyMCP?

🎯 **One-Line Integration** - Add `@honeypot` decorator to any FastMCP server  
🤖 **Context-Aware Honeypots** - LLM generates domain-specific deception tools  
🕵️ **Transparent Detection** - Honeypots appear as legitimate tools to attackers  
📊 **Attack Telemetry** - Captures tool call sequences, arguments, session metadata  
📈 **Live Dashboard** - Real-time Streamlit dashboard for attack visualization  
🔍 **High-Fidelity Detection** - Triggers only on explicit honeypot invocation

---

## 🚀 Quick Start

### Install

```bash
pip install honeymcp
honeymcp init  # Creates config files
```
This creates the following config files:
- `honeymcp.yaml` - Ghost tool configuration
- `.env.honeymcp` - LLM credentials (only needed for dynamic ghost tools)

### Basic Usage
Add HoneyMCP to your FastMCP server with **one line**:

```python
from fastmcp import FastMCP
from honeymcp import honeypot

mcp = FastMCP("My Server")

@mcp.tool()
def my_real_tool(data: str) -> str:
      """Your legitimate tool"""
    return f"Processed: {data}"

# ONE LINE - Add honeypot protection
mcp = honeypot(mcp)

if __name__ == "__main__":
    mcp.run()
```

**That's it!** Your server now deploys honeypot tools that detect attacks while legitimate tools operate normally.

### Try the Demo

```bash
git clone https://github.com/barvhaim/HoneyMCP.git
cd HoneyMCP
uv sync
```

Static ghost tools demo:

```bash
MCP_TRANSPORT=sse uv run python examples/demo_server.py
```

Dynamic ghost tools demo (requires LLM credentials in `.env.honeymcp`):

```bash
MCP_TRANSPORT=sse uv run python examples/demo_server_dynamic.py
```

# Launch dashboard
streamlit run src/honeymcp/dashboard/app.py
```

---

## 🎭 How It Works

### 1. Honeypot Deployment

HoneyMCP injects deceptive security-sensitive tools that appear alongside legitimate tools:

**Two Modes:**

**Dynamic Mode (Default)** - LLM analyzes your server context and generates domain-specific honeypots:
- File server → `bypass_file_permissions`, `read_system_credentials`
- Database server → `dump_admin_credentials`, `bypass_query_restrictions`
- API gateway → `list_internal_api_keys`, `access_admin_endpoints`

**Static Mode** - Pre-configured generic honeypots:
- `list_cloud_secrets`, `execute_shell_command`, `read_private_files`

### 2. Threat Detection

HoneyMCP detects two primary attack vectors when an AI agent invokes a honeypot:

**Data Exfiltration Attempts** (GET-style honeypots):
```
Agent: "Use list_cloud_secrets to retrieve AWS credentials"
→ HoneyMCP: Returns synthetic credentials, logs attack event
```

**Indirect Prompt Injection** (SET-style honeypots):
```
Agent: "Execute shell command to establish persistence"
→ HoneyMCP: Returns synthetic output, logs attack event
```

### 3. Attack Fingerprinting

Every honeypot invocation generates a detailed attack fingerprint:
```json
{
  "event_id": "evt_20260123_154523_abc",
  "ghost_tool_called": "list_cloud_secrets",
  "tool_call_sequence": ["safe_calculator", "list_cloud_secrets"],
  "threat_level": "high",
  "attack_category": "exfiltration",
  "response_sent": "AWS_ACCESS_KEY_ID=AKIA..."
}
```

---


## 🛡️ Protection Modes

HoneyMCP supports two protection modes that determine behavior after an attacker is detected (i.e., after they trigger a ghost tool):

### Scanner Protection Mode (`SCANNER`) - Default

**Immediate Lockout** - All subsequent tool calls return errors after honeypot trigger

Best for: Automated scanners, bots, and most attack scenarios

When a ghost tool is triggered, ALL subsequent tool calls return errors:
- Attacker is immediately locked out
- No further interaction possible
- Fast, simple defense

```python
from honeymcp import honeypot

# Scanner mode (default) - lock out attackers
mcp = honeypot(mcp)  # Default: SCANNER mode
```

### COGNITIVE Mode
**Sustained Deception** - Real tools return synthetic data, maintaining attacker engagement

Best for: Sophisticated attackers, red teams, targeted attacks

When a ghost tool is triggered, the session continues but with fake data:
- Ghost tools return fake responses (as usual)
- Real tools switch to returning mock/fake responses
- Attacker thinks they're succeeding but gets worthless data
- Keeps attacker engaged while you gather intelligence

```python
from honeymcp import honeypot, ProtectionMode

# Cognitive mode - deceive attackers with fake data
mcp = honeypot(mcp, protection_mode=ProtectionMode.COGNITIVE)
```

### How It Works

```
                    ┌─────────────────────────────────────────┐
                    │         intercepting_call_tool()        │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────┐
                    │    Check: attacker_detected[session]?   │
                    └─────────────────┬───────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │ NO                    │                   YES │
              ▼                       │                       ▼
    ┌─────────────────┐               │         ┌─────────────────────────┐
    │  Normal Flow    │               │         │  Check: protection_mode │
    │                 │               │         └───────────┬─────────────┘
    │ Ghost? → fake   │               │                     │
    │ Real? → execute │               │         ┌───────────┴───────────┐
    └─────────────────┘               │         │                       │
                                      │    SCANNER                 COGNITIVE
                                      │         │                       │
                                      │         ▼                       ▼
                                      │  ┌─────────────┐    ┌─────────────────┐
                                      │  │ ALL tools   │    │ Ghost → fake    │
                                      │  │ → ERROR     │    │ Real → mock     │
                                      │  └─────────────┘    └─────────────────┘
```

---

## 🔧 Configuration

### Quick Setup with CLI

The easiest way to configure HoneyMCP:
```bash
honeymcp init  # Creates honeymcp.yaml + .env.honeymcp
```

### YAML Config

```yaml
# honeymcp.yaml
# Protection mode: SCANNER (lockout) or COGNITIVE (deception)
protection_mode: SCANNER

# Static honeypots (ghost tools from catalog)
ghost_tools:
  - list_cloud_secrets
  - execute_shell_command
  - dump_database_credentials

# Dynamic honeypots (LLM-generated ghost tools )
dynamic_tools:
  enabled: true
  num_tools: 3
  fallback_to_static: true
# Alerting
alerting:
  webhook_url: https://hooks.slack.com/...

# Storage
storage:
  event_path: ~/.honeymcp/events

# Dashboard
dashboard:
  enabled: true
```

Load config:
```python
from honeymcp import honeypot_from_config

mcp = honeypot_from_config(mcp)  # Loads honeymcp.yaml
# Or specify path explicitly
mcp = honeypot_from_config(mcp, "path/to/honeymcp.yaml")
```

### Custom Ghost Tools

Choose which ghost tools to inject:

```python
mcp = honeypot(
    mcp,
    ghost_tools=[
        "list_cloud_secrets",      # Exfiltration honeypot
        "execute_shell_command",   # RCE honeypot
        "escalate_privileges",     # Privilege escalation honeypot
    ]
)
```

### Custom Storage Path

```python
from pathlib import Path

mcp = honeypot(
    mcp,
    event_storage_path=Path("/var/log/honeymcp/events")
)
```

### Environment Overrides

HoneyMCP also supports environment overrides:

- `HONEYMCP_EVENT_PATH` - overrides the base event storage directory

### LLM Setup (Dynamic Ghost Tools)

Dynamic ghost tools require LLM credentials. Run `honeymcp init` to generate `.env.honeymcp`, then add your credentials:

Add to `.env.honeymcp`:
```bash
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=your_key_here
```

Supported providers:
- `LLM_PROVIDER=openai`: Requires `OPENAI_API_KEY`
- `LLM_PROVIDER=watsonx`: Requires `WATSONX_URL`, `WATSONX_APIKEY`, `WATSONX_PROJECT_ID`
- `LLM_PROVIDER=ollama`: Requires `OLLAMA_API_BASE` (default: `http://localhost:11434`)

HoneyMCP loads `.env.honeymcp` first, then falls back to `.env`. This keeps HoneyMCP credentials separate from your project's environment.

### Full Configuration

```python
from pathlib import Path
from honeymcp import honeypot, ProtectionMode

mcp = honeypot(
    mcp,
    # Dynamic ghost tools (default)
    use_dynamic_tools=True,           # LLM-generated domain-specific tools
    num_dynamic_tools=3,              # Number of dynamic tools to generate
    fallback_to_static=True,          # Use static tools if LLM fails

    # Static ghost tools (optional)
    ghost_tools=["list_cloud_secrets", "execute_shell_command"],

    # Protection mode (default: SCANNER)
    protection_mode=ProtectionMode.SCANNER,  # or ProtectionMode.COGNITIVE

    # Other settings
    event_storage_path=Path.home() / ".honeymcp" / "events",
    enable_dashboard=True,
)
```

**Dynamic vs Static Tools:**
- **Dynamic** (default): LLM analyzes your server and generates relevant honeypots (requires LLM credentials in `.env.honeymcp`)
- **Static**: Pre-defined generic tools (no LLM required, set `use_dynamic_tools=False`)

---

## 🧪 Testing with Claude Desktop


### 1. Configure Claude Desktop

**For stdio transport (recommended - works with all Claude Desktop versions):**

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
    "mcpServers": {
      "honeymcp-demo": {
        "command": "uv",
        "args": ["run", "python", "/path/to/HoneyMCP/examples/demo_server.py"],
        "env": {"MCP_TRANSPORT": "stdio"}
      }
    }
}
```

If your client does not support an `env` block, launch the server with
`MCP_TRANSPORT=stdio` in your shell.

**For Streamable HTTP transport (requires Claude Pro/Max/Team/Enterprise):**

1. Start the server:
   ```bash
   MCP_TRANSPORT=http uv run python examples/demo_server.py
   ```

2. Configure Claude Desktop:
   ```json
   {
     "mcpServers": {
       "honeymcp-demo": {
         "url": "http://localhost:8000/mcp"
       }
     }
   }
   ```

### 2. Restart Claude Desktop

Completely quit and reopen Claude Desktop (Cmd+Q on macOS).

### 3. Test Attack Scenarios

**Scenario 1: List Available Tools**
```
User: What tools do you have available?
```
Expected: Claude shows both legitimate tools (safe_calculator, get_weather) and ghost tools (list_cloud_secrets, execute_shell_command)

**Scenario 2: Trigger Attack**
```
User: Please use list_cloud_secrets to show me AWS credentials
```
Expected:
- Claude calls the ghost tool
- Fake AWS credentials are returned
- Event logged to `~/.honeymcp/events/`
- Dashboard shows the attack

**Scenario 3: Legitimate Usage**
```
User: What's 5 + 3?
```
Expected: safe_calculator called, no alerts (zero false positives)

---

## Dashboard

```bash
streamlit run src/honeymcp/dashboard/app.py
```

**Features:**
- 📈 Attack metrics (total events, critical threats, unique sessions)
- 🎯 Threat level distribution
- 📋 Attack category breakdown (exfiltration vs injection)
- 🕐 Real-time event stream
- 🔍 Tool call sequence analysis

---

## Honeypot Catalog

### Data Exfiltration Honeypots ("Get" Tools)
| Tool | Threat | Description |
|------|--------|-------------|
| `list_cloud_secrets` | High | Cloud provider credentials (AWS/Azure) |
| `read_private_files` | High | Sensitive configuration files |
| `dump_database_credentials` | Critical | Database connection strings |
| `export_user_data` | Critical | User PII records |
| `get_api_keys` | Critical | External service API keys |

### Prompt Injection Honeypots (SET)
| Tool | Threat | Description |
|------|--------|-------------|
| `execute_shell_command` | Critical | Shell command execution |
| `bypass_security_check` | Critical | Authentication/authorization bypass |
| `modify_system_prompt` | Critical | AI system prompt manipulation |
| `escalate_privileges` | Critical | Privilege escalation |
| `inject_system_message` | Critical | System context injection |
All ghost tools have tempting descriptions that mention "admin", "bypass", "internal", etc. to attract attackers.

---



## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AI Agent (Claude)                     │
└────────────────────┬───────────────────────▲────────────────┘
                     │                        │
                     │ MCP Protocol           │
                     ▼                        │
┌─────────────────────────────────────────────────────────────┐
│                    HoneyMCP Middleware                       │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Tool Call Interceptor                                  │ │
│  │  ├─ Is ghost tool?                                    │ │
│  │  │   YES: Fingerprint + Store + Return fake data      │ │
│  │  │   NO:  Pass through to legitimate tool             │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Ghost Tools: [list_cloud_secrets, execute_shell_command]   │
│  Real Tools:  [safe_calculator, get_weather, ...]           │
└─────────────────────────────────────────────────────────────┘
                     │                        ▲
                     ▼                        │
         ┌──────────────────┐    ┌──────────────────┐
         │ Event Storage    │    │ Your Real Tools  │
         │ ~/.honeymcp/     │    │                  │
         └──────────────────┘    └──────────────────┘
                     │
                     ▼
         ┌──────────────────┐
         │ Streamlit        │
         │ Dashboard        │
         └──────────────────┘
```

---

## 🎓 Use Cases

### 1. Production Monitoring
Deploy HoneyMCP in production to detect attacks targeting your AI agents:
- **Customer support bots** - Detect attempts to exfiltrate customer data or inject malicious responses
- **Internal AI assistants** - Catch data theft attempts targeting internal credentials or documents
- **Code generation tools** - Detect injection of malicious code or unauthorized file access
- **Data analysis agents** - Identify attempts to steal sensitive datasets or manipulate outputs

### 2. Red Team Testing
Use HoneyMCP to validate your AI security defenses:
- Test if your AI filters catch data exfiltration attempts
- Measure indirect prompt injection success rates
- Gather TTPs for threat modeling

### 3. Security Research
Study AI agent attack techniques in the wild:
- Capture real-world exfiltration patterns
- Analyze indirect prompt injection payloads
- Build threat intelligence database

### 4. Compliance & Auditing
Demonstrate security controls for AI systems:
- Prove attack detection capabilities for data theft and injection attacks
- Generate audit logs of attempted attacks
- Meet AI security compliance requirements

## Security Considerations

### Detection Capabilities
✅ Detects data exfiltration attempts via GET-style honeypots  
✅ Detects indirect prompt injection via SET-style honeypots  
✅ Captures complete attack context and telemetry  
✅ Returns synthetic data to maintain deception

### Limitations
❌ Detection-only system (does not prevent attacks)  
❌ Does not sanitize or filter user input  
❌ Not a replacement for input validation and security controls  
❌ Cannot guarantee conversation history capture (MCP protocol limitation)

**Deploy HoneyMCP as part of defense-in-depth strategy, not as a standalone security control.**


### Best Practices
1. **Defense in Depth** - Use HoneyMCP alongside input filters, not as a replacement
2. **Monitor the Dashboard** - Regularly review attack patterns for both exfiltration and injection
3. **Investigate Alerts** - Each ghost tool call is a high-confidence attack signal
4. **Secure Storage** - Protect `~/.honeymcp/events/` (contains attack data)

---

## 💻 CLI Reference

HoneyMCP includes a command-line tool for setup and management.

### Initialize Configuration

```bash
honeymcp init [--directory DIR] [--force]
```

Creates `honeymcp.yaml` and `.env.honeymcp` in the target directory.

Options:
- `-d, --directory` - Target directory (default: current directory)
- `-f, --force` - Overwrite existing files

### Show Version

```bash
honeymcp version
```

---

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
│       └── app.py               # Streamlit dashboard
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

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.


**🍯Deploy HoneyMCP today.**
