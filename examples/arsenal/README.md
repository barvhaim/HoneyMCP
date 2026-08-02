# HoneyMCP — Black Hat Arsenal demo

A booth-ready demo: one command runs a scripted attack against a HoneyMCP-protected
HR MCP server and streams the captured events into the live dashboard.

## Run it

```bash
uv run python examples/arsenal/run_demo.py
```

Then open **http://127.0.0.1:8001/dashboard** side by side with the terminal.
Ctrl-C when you're done presenting.

### The one command to memorize

If the network is hostile or you want a guaranteed-identical run:

```bash
uv run python examples/arsenal/run_demo.py --static
```

`--static` skips the LLM entirely. **Use this if the LLM endpoint in your `.env`
is unreachable from the venue** — the default tries live honeypot generation
first. It falls back automatically, so `--static` is about a predictable run
rather than a working one.

### Live honeypot generation

The default path asks an LLM to invent honeypots that fit *this* server's domain,
which is the stronger story: the demo triggers a generated tool
(`bypass_rbac_check`, `export_privileged_credentials`, …) rather than a static
catalog name. Point it at any OpenAI-compatible endpoint:

```bash
export LLM_PROVIDER=openai
export OPENAI_BASE_URL=http://localhost:8989/v1   # your endpoint
export OPENAI_API_KEY=any-value
export LLM_MODEL=premium                          # your model name
uv run python examples/arsenal/run_demo.py
```

`OPENAI_BASE_URL` is read by `ChatOpenAI` directly — HoneyMCP's `openai` provider
branch does not set a base URL itself, so this env var is how you redirect it off
`api.openai.com`. Verify before the talk: the summary line reads
`Honeypots deployed 6 (LLM-generated (live))` when generation worked.

### Flags

| Flag | Effect |
|---|---|
| `--static` | Static catalog honeypots, no LLM call. Offline-safe, deterministic. |
| `--no-dashboard` | Terminal only. |
| `--slow` / `--fast` | Narration pacing. `--slow` for a live audience. |
| `--keep-events` | Don't wipe events from earlier runs. |
| `--event-path DIR` | Where demo events go. Defaults under `$TMPDIR`. |

`ARSENAL_VERBOSE=1` restores the suppressed LLM tracebacks when debugging.

## What the demo shows

1. **Recon** — the agent lists tools. Real HR tools and honeypots are
   indistinguishable in the listing. This is the core idea; let it land.
2. **A legitimate call** — `list_departments()` succeeds, logs nothing, alerts
   nobody. Zero false positives is a design invariant, and worth saying out loud.
3. **The grab** — the agent calls a honeypot, gets convincing fake data, and
   believes it won.
4. **Follow-up** — the agent probes a real tool again and is **blocked**. SCANNER
   mode burned the session the moment the honeypot fired.
5. **The forensic record** — the captured `AttackFingerprint`: event id, session,
   `threat_level: critical`, the attack category, the exact arguments used, and
   the `call_sequence` leading up to the grab.

The framing that works: *the attacker never touched real data, and the defender
walks away with a full record of the attempt.*

Step 4 prints the lockout line **only if** a block really happens, so the
narration stays truthful if enforcement ever regresses. It regressed silently
once before (see below), which is why it is asserted in
`tests/test_protection_mode_enforcement.py` rather than trusted.

## Two bugs this demo surfaced

Both fixed on `fix/fastmcp3-middleware-dispatch`; worth knowing in case a
question comes from the floor.

**1. Enforcement never ran on the live path.** FastMCP 3.x dispatches protocol
tool calls through its provider/middleware chain, not through the
`server.call_tool` attribute `honeypot()` monkey-patched. Ghost tools still fired
(they're registered as ordinary tools), but lockout, COGNITIVE mocks, rate
limiting, allowlist bypass and `tool_call_sequence` all silently no-op'd. Fix:
register a real FastMCP `Middleware` with `on_call_tool`, keeping the attribute
patch as the 2.x fallback.

**2. The fallback session id was regenerated per call.** Under stdio the
transport supplies no session identity, and the fallback minted a fresh UUID
every call — so `mark_attacker()` wrote one key and `is_attacker()` read another.
Nothing session-scoped could ever have worked over stdio. Fix: one stable id per
process.

`tests/test_protection_modes.py` only asserts on the enum, which is why 241 tests
stayed green through both.

## Booth troubleshooting

**Dashboard shows old events, or none from this run.**
The most likely cause is an event-path mismatch. The repo's `honeymcp.yaml` sets
`storage.event_path: ~/.honeymcp/events`, and that explicit value outranks
`HONEYMCP_EVENT_PATH`. `run_demo.py` works around it by launching uvicorn from a
scratch cwd with no `honeymcp.yaml`. If you start the dashboard yourself with
`make run-ui`, it will read `~/.honeymcp/events` instead and you'll see the wrong
data.

**Port 8001 already in use.** The script reuses whatever is there and warns you.
If that's an older dashboard on a different event path, kill it first:
`lsof -ti:8001 | xargs kill -9`.

**Honeypots are the static three, not HR-flavored.** LLM generation failed and it
fell back — the run is still valid, and the summary line tells you which path was
taken. Check the endpoint env vars above, then
`ARSENAL_VERBOSE=1 … --no-dashboard` to see the real error. The spawned server's
stderr is also always captured to `<event-path>/../server.log`.

**Nothing appears at all.** Fall back to
`uv run python examples/arsenal/run_demo.py --static --no-dashboard`, which has no
network or browser dependency.

## Files

- `run_demo.py` — orchestrator: dashboard, attack driver, narration.
- `hr_server.py` — the target. An ordinary HR MCP server plus one `honeypot()` call.
