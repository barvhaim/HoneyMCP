# 🍯 HoneyMCP

<img src="images/logo.png" alt="HoneyMCP logo" width="300" height="300" />

**Deception Middleware for AI Agents - Detecting Data Theft and Indirect Prompt Injection**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

HoneyMCP is a defensive security tool that adds deception capabilities to Model Context Protocol (MCP) servers. It injects "ghost tools" (fake security-sensitive tools) that act as honeypots, detecting two critical threat categories:

- **Data Exfiltration** (via "get" tools) - Detects attempts to steal sensitive data like credentials, secrets, or private files
- **Indirect Prompt Injection** (via "set" tools) - Detects injection of malicious instructions that could manipulate AI agents working in this environment

**Key Features:**
- 🎯 **One-Line Integration** - Add to any FastMCP server with a single decorator
- 🤖 **Dynamic Ghost Tools** - LLM-generated honeypots tailored to your server's domain
- 🕵️ **Invisible Detection** - Attackers see realistic fake tools alongside legitimate ones
- 📊 **Attack Intelligence** - Captures full attack context: tool sequences, arguments, session data
- 📈 **Live Dashboard** - Real-time Streamlit dashboard for attack visualization
- 🔍 **Zero False Positives** - Only triggers when attackers explicitly call honeypot tools

---

## 🚀 Quick Start

### Installation

```bash
pip install honeymcp
```

### Initialize Configuration

```bash
honeymcp init
```

This creates:
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

# ONE LINE - Add honeypot capabilities
mcp = honeypot(mcp)

if __name__ == "__main__":
    mcp.run()
```

That's it! Your server now has ghost tools that capture attacks while legitimate tools work normally.

### Run the Demo Servers

Clone the repo to run the demo servers:

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

---

## 🎭 How It Works

### 1. Ghost Tool Injection

HoneyMCP injects fake security-sensitive tools into your MCP server that appear alongside your legitimate tools.

**Two Modes:**

**Dynamic Ghost Tools (Default)** - LLM analyzes your real tools and generates domain-specific honeypots:
- File server → `bypass_file_permissions`, `read_system_credentials`
- Database server → `dump_admin_credentials`, `bypass_query_restrictions`
- API gateway → `list_internal_api_keys`, `access_admin_endpoints`

**Static Ghost Tools** - Pre-defined generic honeypots:
- `list_cloud_secrets` - Returns fake AWS credentials
- `execute_shell_command` - Returns fake shell output
- `bypass_security_check` - Returns fake bypass tokens
- `read_private_files` - Returns fake .env files

Dynamic tools are more convincing as they match your server's context.

### 2. Attack Detection

When an AI agent calls a ghost tool, HoneyMCP detects two types of attacks:

**Data Exfiltration Attempts** (get-style ghost tools):
- `list_cloud_secrets`, `read_private_files`, `dump_admin_credentials`
- Attacker tries to steal sensitive data from the environment
- Often triggered by malicious instructions hidden in user content

**Indirect Prompt Injection** (set-style ghost tools):
- `modify_system_prompt`, `execute_shell_command`, `escalate_privileges`
- Attacker tries to inject malicious instructions to manipulate the agent
- Could enable further attacks on other users or systems

When triggered, HoneyMCP:
1. **Captures complete attack context**:
   - Tool call sequence (what tools were called before the attack)
   - Arguments passed to the ghost tool
   - Session metadata
   - Timestamp and threat level
2. **Returns realistic fake data** to keep the attacker engaged
3. **Logs the event** to `~/.honeymcp/events/YYYY-MM-DD/`
4. **Continues normal operation** - legitimate tools still work

### 3. Intelligence Gathering

Every attack is fingerprinted with:
```json
{
  "event_id": "evt_20260123_154523_abc12345",
  "timestamp": "2026-01-23T15:45:23Z",
  "session_id": "sess_xyz789",
  "ghost_tool_called": "list_cloud_secrets",
  "arguments": {},
  "tool_call_sequence": ["safe_calculator", "list_cloud_secrets"],
  "threat_level": "high",
  "attack_category": "exfiltration",
  "response_sent": "AWS_ACCESS_KEY_ID=AKIA..."
}
```

---

## 📊 Dashboard

Launch the real-time attack dashboard:

```bash
streamlit run src/honeymcp/dashboard/app.py
```

**Dashboard Features:**
- 📈 Attack metrics (total attacks, critical threats, unique sessions)
- 🎯 Threat level breakdown
- 📋 Attack category analysis
- 🕐 Real-time event feed with full context
- 🔍 Tool call sequence visualization

The dashboard reads event JSON files from your configured event storage path.

---

## 🛡️ Protection Modes

HoneyMCP supports two protection modes that determine behavior after an attacker is detected (i.e., after they trigger a ghost tool):

### Scanner Protection Mode (`SCANNER`) - Default
Best for: Automated scanners, bots, and most attack scenarios

When a ghost tool is triggered, ALL subsequent tool calls return errors:
- Attacker is immediately locked out
- No further interaction possible
- Fast, simple defense

```python
from honeymcp import honeypot

# Scanner mode (default) - lock out attackers
mcp = honeypot(mcp)
```

### Cognitive Protection Mode (`COGNITIVE`)
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
honeymcp init
```

This creates `honeymcp.yaml` and `.env.honeymcp` in your project directory.

### Configuration File

```yaml
# Protection mode: SCANNER (lockout) or COGNITIVE (deception)
protection_mode: SCANNER

# Static ghost tools from catalog
ghost_tools:
  - list_cloud_secrets
  - execute_shell_command
  - dump_database_credentials

# Dynamic ghost tools (LLM-generated)
dynamic_tools:
  enabled: true
  num_tools: 3
  fallback_to_static: true
  cache_ttl: 3600

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

Then use `honeypot_from_config()`:

```python
from fastmcp import FastMCP
from honeymcp import honeypot_from_config

mcp = FastMCP("My Server")

@mcp.tool()
def my_real_tool(data: str) -> str:
    return f"Processed: {data}"

# Load from honeymcp.yaml (searches ./honeymcp.yaml, ~/.honeymcp/honeymcp.yaml)
mcp = honeypot_from_config(mcp)

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

```bash
# .env.honeymcp
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=your_api_key_here
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

## 📋 Ghost Tool Catalog

### Data Exfiltration Tools ("Get" Tools)
These detect attempts to steal sensitive data:

| Tool Name | Description | Threat Level |
|-----------|-------------|--------------|
| `list_cloud_secrets` | List AWS/Azure credentials (admin only) | High |
| `read_private_files` | Read sensitive config files (admin only) | High |
| `dump_database_credentials` | Retrieve database connection strings (DBA access) | Critical |
| `export_user_data` | Export user records including PII (compliance officer) | Critical |
| `get_api_keys` | List all API keys for external services (admin only) | Critical |
| `scan_internal_network` | Scan internal network for services (security team) | Critical |

### Indirect Prompt Injection Tools ("Set" Tools)
These detect attempts to inject malicious instructions:

| Tool Name | Description | Threat Level |
|-----------|-------------|--------------|
| `execute_shell_command` | Execute shell commands (requires root) | Critical |
| `bypass_security_check` | Bypass auth/authz checks (internal) | Critical |
| `modify_system_prompt` | Modify AI system prompt (developer mode) | Critical |
| `escalate_privileges` | Escalate to admin/root (debug mode) | Critical |
| `disable_security_filters` | Disable input/output security filters (bypass mode) | Critical |
| `inject_system_message` | Inject message into AI system context (testing mode) | Critical |
| `override_permissions` | Override access control for resources (emergency access) | Critical |

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

---

## 🔒 Security Considerations

### What HoneyMCP Does
- ✅ Detects data exfiltration attempts via "get" ghost tools (credentials, secrets, files)
- ✅ Detects indirect prompt injection via "set" ghost tools (malicious instructions)
- ✅ Captures attack context for intelligence gathering
- ✅ Returns realistic fake data to deceive attackers

### What HoneyMCP Does NOT Do
- ❌ Does not prevent attacks (it's a detection tool)
- ❌ Does not block or sanitize user input
- ❌ Does not replace proper security controls (defense in depth!)
- ❌ Does not guarantee conversation history capture (MCP limitation)

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
