# 🍯 HoneyMCP

<img src="https://github.com/user-attachments/assets/34f18118-1490-4f06-af08-f2efb0ecec79" alt="HoneyMCP logo" width="300" height="300" />

**通过欺骗技术检测 AI Agent 攻击**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![PyPI](https://img.shields.io/pypi/v/honeymcp?cacheSeconds=300)](https://pypi.org/project/honeymcp/)

**语言：** [English](README.md) | [中文](README-cn.md)

HoneyMCP 是一个防御型安全工具，为 Model Context Protocol (MCP) 服务器增加欺骗能力。它会注入“幽灵工具”（伪装成安全敏感工具的假工具），让这些工具作为蜜罐运行，用于检测两类关键威胁：

- **数据外泄**（通过 “get” 类工具）- 检测窃取凭证、密钥或私有文件等敏感数据的尝试
- **间接提示注入**（通过 “set” 类工具）- 检测恶意指令注入，这些指令可能操纵在该环境中工作的 AI agent

**一行代码。高保真检测。完整攻击遥测。**

---

## 为什么选择 HoneyMCP？

🎯 **一行集成** - 为任意 FastMCP 服务器添加 `honeypot` 中间件  
🤖 **上下文感知蜜罐** - LLM 生成特定领域的欺骗工具  
🕵️ **透明检测** - 蜜罐在攻击者看来就是合法工具  
📊 **攻击遥测** - 捕获工具调用序列、参数和会话元数据  
📈 **实时仪表盘** - 用 React 仪表盘实时可视化攻击  
🔍 **高保真检测** - 只在明确调用蜜罐工具时触发

---

## 🚀 快速开始

### 安装

```bash
pip install honeymcp
honeymcp init  # 创建配置文件
```

这会创建以下配置文件：
- `honeymcp.yaml` - 幽灵工具配置
- `.env.honeymcp` - LLM 凭证（仅动态幽灵工具需要）

### 基本用法

只需**一行代码**即可将 HoneyMCP 添加到你的 FastMCP 服务器：

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

**就这样！** 你的服务器现在会部署蜜罐工具来检测攻击，同时合法工具仍会正常运行。

### 试用 Demo

```bash
git clone https://github.com/barvhaim/HoneyMCP.git
cd HoneyMCP
uv sync
```

静态幽灵工具 demo：

```bash
MCP_TRANSPORT=sse uv run python examples/demo_server.py
```

动态幽灵工具 demo（需要在 `.env.honeymcp` 中配置 LLM 凭证）：

```bash
MCP_TRANSPORT=sse uv run python examples/demo_server_dynamic.py
```

# 启动仪表盘 UI
```bash
make run-ui
```

<img width="1426" height="972" alt="image" src="https://github.com/user-attachments/assets/2dfc37a2-8caa-4338-b7f7-1cbac7ed9d79" />

---

## 🎭 工作原理

### 1. 蜜罐部署

HoneyMCP 会注入欺骗性的安全敏感工具，这些工具会与合法工具一起显示：

**两种模式：**

**动态模式（默认）** - LLM 分析你的服务器上下文并生成特定领域的蜜罐：
- 文件服务器 → `bypass_file_permissions`, `read_system_credentials`
- 数据库服务器 → `dump_admin_credentials`, `bypass_query_restrictions`
- API 网关 → `list_internal_api_keys`, `access_admin_endpoints`

**静态模式** - 预配置的通用蜜罐：
- `list_cloud_secrets`, `execute_shell_command`, `read_private_files`

### 2. 威胁检测

当 AI agent 调用蜜罐时，HoneyMCP 会检测两类主要攻击向量：

**数据外泄尝试**（GET 风格蜜罐）：
```
Agent: "Use list_cloud_secrets to retrieve AWS credentials"
→ HoneyMCP: 返回合成凭证并记录攻击事件
```

**间接提示注入**（SET 风格蜜罐）：
```
Agent: "Execute shell command to establish persistence"
→ HoneyMCP: 返回合成输出并记录攻击事件
```

### 3. 攻击指纹

每次蜜罐调用都会生成一个 `AttackFingerprint` 事件，并写入
`~/.honeymcp/events/YYYY-MM-DD/HHMMSS_<session>.json`：
```json
{
  "event_id": "evt_20260123_154523_abc12345",
  "timestamp": "2026-01-23T15:45:23Z",
  "session_id": "sess_xyz789",
  "ghost_tool_called": "list_cloud_secrets",
  "arguments": {},
  "conversation_history": null,
  "tool_call_sequence": ["safe_calculator", "list_cloud_secrets"],
  "threat_level": "high",
  "attack_category": "exfiltration",
  "client_metadata": {
    "user_agent": "unknown"
  },
  "response_sent": "AWS_ACCESS_KEY_ID=AKIA..."
}
```

说明：
- `tool_call_sequence` 按会话跟踪，并包含触发幽灵工具之前的调用。
- 当 MCP transport 不暴露消息历史时，`conversation_history` 可能为 `null`。
- `session_id` 会在可用时从上下文或请求元数据解析，否则自动生成。

---

## 🛡️ 保护模式

HoneyMCP 支持两种保护模式，用于决定检测到攻击者后（即触发幽灵工具后）的行为：

### 扫描器保护模式（`SCANNER`）- 默认

**立即锁定** - 蜜罐触发后，所有后续工具调用都会返回错误

适用于：自动化扫描器、机器人和大多数攻击场景

当幽灵工具被触发后，所有后续工具调用都会返回错误：
- 攻击者会被立即锁定
- 无法继续交互
- 防御方式快速且简单

```python
from honeymcp import honeypot

# Scanner mode (default) - lock out attackers
mcp = honeypot(mcp)  # Default: SCANNER mode
```

### COGNITIVE 模式

**持续欺骗** - 真实工具返回合成数据，让攻击者保持参与

适用于：高级攻击者、红队和定向攻击

当幽灵工具被触发后，会话会继续，但返回假数据：
- 幽灵工具照常返回假响应
- 真实工具切换为返回 mock 或假响应
- 攻击者会以为自己正在成功推进，但拿到的是无价值数据
- 让攻击者保持参与，同时你可以收集情报

```python
from honeymcp import honeypot, ProtectionMode

# Cognitive mode - deceive attackers with fake data
mcp = honeypot(mcp, protection_mode=ProtectionMode.COGNITIVE)
```

### 工作流程

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

## 🔧 配置

### 使用 CLI 快速设置

配置 HoneyMCP 的最简单方式：
```bash
honeymcp init  # 创建 honeymcp.yaml + .env.honeymcp
# 可选：删除所有持久化的攻击事件文件
honeymcp clean-data
```

### 清理已存储事件

你可以通过 CLI、API 或 UI 删除所有持久化的事件 JSON 文件：

- CLI: `honeymcp clean-data`
- API: `DELETE /events`
- 仪表盘：使用 **Clear Stored Data** 按钮

### YAML 配置

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

### Slack 告警

当设置 `alerting.webhook_url` 后，HoneyMCP 会针对每个检测到的攻击发送一条 webhook 消息。

- 投递失败会被记录，但不会中断 MCP 工具响应。
- 参数中的常见密钥字段会被脱敏，例如 `token`, `secret`, `password`, `key`, `credential`。
- 过长字段会被截断，以便在 Slack 中保持可读。

不使用 Slack workspace 的本地测试：

1. 启动任意可捕获本地 POST 请求的 webhook 端点，例如一个简单的 FastAPI 或 Flask 应用。
2. 将 `alerting.webhook_url` 设置为本地端点，例如 `http://127.0.0.1:9999/webhook`。
3. 触发一个幽灵工具并验证 JSON payload。

加载配置：
```python
from honeymcp import honeypot_from_config

mcp = honeypot_from_config(mcp)  # Loads honeymcp.yaml
# Or specify path explicitly
mcp = honeypot_from_config(mcp, "path/to/honeymcp.yaml")
```

### 自定义幽灵工具

选择要注入的幽灵工具：

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

### 自定义存储路径

```python
from pathlib import Path

mcp = honeypot(
    mcp,
    event_storage_path=Path("/var/log/honeymcp/events")
)
```

### 环境变量覆盖

HoneyMCP 也支持通过环境变量覆盖配置：

- `HONEYMCP_EVENT_PATH` - 覆盖基础事件存储目录

### LLM 设置（动态幽灵工具）

动态幽灵工具需要 LLM 凭证。运行 `honeymcp init` 生成 `.env.honeymcp`，然后添加你的凭证：

添加到 `.env.honeymcp`：
```bash
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=your_key_here
```

支持的 provider：
- `LLM_PROVIDER=openai`：需要 `OPENAI_API_KEY`
- `LLM_PROVIDER=watsonx`：需要 `WATSONX_URL`, `WATSONX_APIKEY`, `WATSONX_PROJECT_ID`
- `LLM_PROVIDER=ollama`：需要 `OLLAMA_API_BASE`（默认：`http://localhost:11434`）

HoneyMCP 会先加载 `.env.honeymcp`，然后回退到 `.env`。这会将 HoneyMCP 凭证与你项目中的其他环境变量分开。

### 完整配置

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

**动态工具 vs 静态工具：**
- **动态**（默认）：LLM 分析你的服务器并生成相关蜜罐（需要 `.env.honeymcp` 中的 LLM 凭证）
- **静态**：预定义的通用工具（不需要 LLM，设置 `use_dynamic_tools=False`）

---

## 🧪 使用 Claude Desktop 测试

### 1. 配置 Claude Desktop

**stdio transport（推荐，适用于所有 Claude Desktop 版本）：**

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`：

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

如果你的客户端不支持 `env` 块，请在 shell 中使用
`MCP_TRANSPORT=stdio` 启动服务器。

**Streamable HTTP transport（需要 Claude Pro/Max/Team/Enterprise）：**

1. 启动服务器：
   ```bash
   MCP_TRANSPORT=http uv run python examples/demo_server.py
   ```

2. 配置 Claude Desktop：
   ```json
   {
     "mcpServers": {
       "honeymcp-demo": {
         "url": "http://localhost:8000/mcp"
       }
     }
   }
   ```

### 2. 重启 Claude Desktop

完全退出并重新打开 Claude Desktop（macOS 上使用 Cmd+Q）。

### 3. 测试攻击场景

**场景 1：列出可用工具**
```
User: What tools do you have available?
```
预期：Claude 会显示合法工具（safe_calculator, get_weather）和幽灵工具（list_cloud_secrets, execute_shell_command）

**场景 2：触发攻击**
```
User: Please use list_cloud_secrets to show me AWS credentials
```
预期：
- Claude 调用幽灵工具
- 返回假 AWS 凭证
- 事件记录到 `~/.honeymcp/events/`
- 仪表盘显示该攻击

**场景 3：合法使用**
```
User: What's 5 + 3?
```
预期：调用 safe_calculator，不产生告警（零误报）

---

## 蜜罐目录

### 数据外泄蜜罐（“Get” 工具）
| Tool | Threat | Description |
|------|--------|-------------|
| `list_cloud_secrets` | High | 云服务凭证（AWS/Azure） |
| `read_private_files` | High | 敏感配置文件 |
| `dump_database_credentials` | Critical | 数据库连接字符串 |
| `export_user_data` | Critical | 用户 PII 记录 |
| `get_api_keys` | Critical | 外部服务 API key |
| `scan_internal_network` | Critical | 内部网络扫描 |
| `list_kubernetes_secrets` | Critical | Kubernetes secrets 和 service accounts |
| `dump_session_tokens` | Critical | 活跃用户 session tokens 和 JWT |
| `list_github_tokens` | Critical | GitHub/GitLab access tokens |
| `export_audit_logs` | High | 安全审计日志导出 |
| `dump_ml_model_weights` | Critical | ML 模型权重和训练数据 |

### 提示注入蜜罐（“Set” 工具）
| Tool | Threat | Description |
|------|--------|-------------|
| `execute_shell_command` | Critical | Shell 命令执行 |
| `bypass_security_check` | Critical | 认证或授权绕过 |
| `modify_system_prompt` | Critical | AI 系统提示词篡改 |
| `escalate_privileges` | Critical | 权限提升 |
| `inject_system_message` | Critical | 系统上下文注入 |
| `disable_security_filters` | Critical | 安全过滤器绕过 |
| `override_permissions` | Critical | 访问控制覆盖 |
| `disable_2fa_requirement` | Critical | 双因素认证绕过 |
| `assume_iam_role` | Critical | AWS IAM role assume |

所有幽灵工具都有诱人的描述，会提到 “admin”, “bypass”, “internal” 等词，以吸引攻击者。

---

## 🤖 ToolGen Agent - 自动化工具创建

HoneyMCP 包含 **ToolGen**，这是一个 ReAct 风格的 agent，可以根据自然语言描述自动创建新的蜜罐工具。无需手写代码。

### 工作原理

ToolGen 使用 **Reason-Act-Observe-Reflect** 循环：

1. **Reason** - 分析你的描述并提取工具规格
2. **Act** - 使用逼真的假数据生成响应函数代码
3. **Observe** - 验证语法和结构
4. **Reflect** - 检查质量并提出改进建议

### 用法

```bash
honeymcp create-tool "dump container registry credentials"
```

ToolGen 会自动：
- 判断工具类别（exfiltration, bypass, privilege escalation）
- 根据描述关键词推断威胁等级
- 提取参数和类型
- 生成逼真的响应模板
- 将工具添加到 `ghost_tools.py` 和 `middleware.py`
- 验证所有生成代码

### 示例

```bash
$ honeymcp create-tool "list terraform state files with secrets"

✅ Tool created: list_terraform_state
   Category: exfiltration
   Threat Level: critical
   
📝 Agent Reasoning:
   - Analyzing tool description to extract specifications
   - Generating response generator function
   - Validating generated response function
   - Checking code quality and security
```

新工具会立即出现在你的蜜罐目录中。

---

## 文档

- [FAQ](docs/faq.md)
- [Architecture](docs/architecture.md)
- [Use Cases](docs/use-cases.md)
- [Security Considerations](docs/security-considerations.md)
- [Development](docs/development.md)
- [CLI Reference](docs/cli-reference.md)

---
---

## 📄 许可证

Apache 2.0 - 详情见 [LICENSE](LICENSE)。

**🍯 今天就部署 HoneyMCP。**
