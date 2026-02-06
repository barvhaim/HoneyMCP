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
         │ React            │
         │ Dashboard        │
         └──────────────────┘
```
