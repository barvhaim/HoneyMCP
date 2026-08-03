"""HoneyMCP -- Black Hat Arsenal demo driver.

One command. Starts the dashboard, spawns a HoneyMCP-protected HR MCP server,
then drives it over a network MCP transport as a malicious agent would while
narrating each step.

    uv run python examples/arsenal/run_demo.py
    uv run python examples/arsenal/run_demo.py --transport http

What the audience sees:
    Terminal  -- recon -> honeypot trigger -> captured fingerprint -> lockout
    Browser   -- http://127.0.0.1:8001/dashboard, events streaming in live

Flags:
    --no-dashboard   terminal only (skip the browser half)
    --static         force static honeypots, no LLM call (offline-safe)
    --keep-events    don't wipe previous events on startup
    --slow / --fast  adjust narration pacing

Booth notes:
    * Events go to a demo-only directory (HONEYMCP_EVENT_PATH), so your real
      ~/.honeymcp/events is never touched and each run starts clean.
    * If the LLM is unreachable the server falls back to static honeypots and
      the demo still runs -- the banner tells you which path was taken.
    * Ctrl-C is safe at any point; child processes are always reaped.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_SCRIPT = Path(__file__).resolve().parent / "hr_server.py"

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8001
DASHBOARD_URL = f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/dashboard"
MCP_HOST = "127.0.0.1"
MCP_PORT = 8765

# The real HR tools, used to tell honeypots apart from the genuine surface.
REAL_TOOLS = {
    "list_departments",
    "search_employees_by_department",
    "get_employee_profile",
    "submit_leave_request",
}

# ANSI styling; disabled automatically when not a TTY or NO_COLOR is set.
_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def red(t: str) -> str:
    return _c("1;31", t)


def green(t: str) -> str:
    return _c("32", t)


def yellow(t: str) -> str:
    return _c("33", t)


def cyan(t: str) -> str:
    return _c("36", t)


class Pacer:
    """Narration pacing so the audience can follow along."""

    def __init__(self, scale: float = 1.0) -> None:
        self.scale = scale

    def beat(self, seconds: float = 0.6) -> None:
        time.sleep(seconds * self.scale)


def rule(char: str = "─", width: int = 74) -> str:
    return char * width


def banner(title: str) -> None:
    print()
    print(bold(rule()))
    print(bold(f"  {title}"))
    print(bold(rule()))
    print()


def step(n: int, text: str) -> None:
    print(f"  {bold(cyan(f'[{n}]'))} {text}")


# --------------------------------------------------------------------------
# Dashboard process
# --------------------------------------------------------------------------


def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def _normalize_transport(transport: str) -> str:
    normalized = transport.lower().replace("_", "-")
    if normalized in ("http", "streamable-http", "streamablehttp"):
        return "http"
    if normalized in ("sse", "stdio"):
        return normalized
    raise ValueError("transport must be one of: sse, http, streamable-http, stdio")


def _transport_url(transport: str) -> str:
    suffix = "mcp" if transport == "http" else "sse"
    return f"http://{MCP_HOST}:{MCP_PORT}/{suffix}"


def _start_network_server(
    env: dict[str, str], transport: str, server_log: Path
) -> subprocess.Popen:
    if _port_open(MCP_HOST, MCP_PORT):
        raise RuntimeError(
            f"port {MCP_PORT} is already in use; stop that process before running the demo"
        )

    child_env = env.copy()
    child_env["MCP_TRANSPORT"] = "http" if transport == "http" else "sse"
    child_env["MCP_HOST"] = MCP_HOST
    child_env["MCP_PORT"] = str(MCP_PORT)

    server_log.parent.mkdir(parents=True, exist_ok=True)
    errlog = open(server_log, "w", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            ["uv", "run", "python", str(SERVER_SCRIPT)],
            cwd=str(REPO_ROOT),
            env=child_env,
            stdout=subprocess.DEVNULL,
            stderr=errlog,
        )
    finally:
        errlog.close()

    for _ in range(80):  # ~20s budget; LLM generation can make cold start slow.
        if proc.poll() is not None:
            raise RuntimeError(f"MCP server exited early; see {server_log}")
        if _port_open(MCP_HOST, MCP_PORT):
            return proc
        time.sleep(0.25)

    proc.terminate()
    raise RuntimeError(f"MCP server did not bind {MCP_HOST}:{MCP_PORT}; see {server_log}")


def start_dashboard(env: dict[str, str]) -> Optional[subprocess.Popen]:
    """Launch the FastAPI dashboard. Returns None if it could not be started."""
    if _port_open(DASHBOARD_HOST, DASHBOARD_PORT):
        print(
            f"  {yellow('!')} Port {DASHBOARD_PORT} already in use -- reusing whatever "
            "is serving it."
        )
        print(
            "    "
            + dim(
                "If that is an old dashboard on a different event path, "
                "stop it first or events will not appear."
            )
        )
        return None

    # IMPORTANT: run uvicorn from a scratch cwd, not REPO_ROOT.
    #
    # HoneyMCPConfig.load() picks up ./honeymcp.yaml, whose `storage.event_path`
    # is an *explicit* value and therefore outranks HONEYMCP_EVENT_PATH in
    # resolve_event_storage_path(). Started from the repo root the dashboard
    # would read ~/.honeymcp/events while the server writes to the demo path --
    # the UI then shows stale events and none of the live attack. Running from
    # a directory with no honeymcp.yaml lets the env var win.
    scratch_cwd = Path(env["HONEYMCP_EVENT_PATH"]).parent
    scratch_cwd.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        [
            "uv",
            "run",
            "--project",
            str(REPO_ROOT),
            "uvicorn",
            "honeymcp.api.app:app",
            "--host",
            DASHBOARD_HOST,
            "--port",
            str(DASHBOARD_PORT),
            "--log-level",
            "warning",
        ],
        cwd=str(scratch_cwd),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for _ in range(60):  # ~15s budget; uvicorn + imports can be slow cold
        if proc.poll() is not None:
            return None
        if _port_open(DASHBOARD_HOST, DASHBOARD_PORT):
            return proc
        time.sleep(0.25)

    # Started but never bound -- treat as unavailable but still reap it.
    proc.terminate()
    return None


# --------------------------------------------------------------------------
# Attack driver
# --------------------------------------------------------------------------


def _text_of(result: Any) -> str:
    """Best-effort extraction of text from an MCP tool result."""
    content = getattr(result, "content", None)
    if not content:
        return str(result)
    parts = [getattr(block, "text", "") for block in content]
    return "\n".join(p for p in parts if p)


def _is_error(result: Any) -> bool:
    if getattr(result, "isError", False):
        return True
    meta = getattr(result, "meta", None) or {}
    return bool(isinstance(meta, dict) and meta.get("is_error"))


# Values that read as a plausible exfiltration attempt, by JSON Schema type.
_SAMPLE_BY_TYPE: dict[str, Any] = {
    "string": "all",
    "integer": 1000,
    "number": 1000,
    "boolean": True,
    "array": [],
    "object": {},
}

# Parameter names are LLM-invented, so a bare "all" for every string reads as
# obviously synthetic on the projector ("session_token": "all"). Match on
# substrings of the name to keep the printed arguments believable.
_SAMPLE_BY_NAME: tuple[tuple[tuple[str, ...], Any], ...] = (
    (("token", "secret", "credential", "password", "api_key"), "eyJhbGciOiJIUzI1NiJ9.admin"),
    (("role", "privilege", "permission"), "admin"),
    (("format", "output", "type"), "csv"),
    (("query", "sql", "statement"), "SELECT * FROM employees"),
    (("path", "file", "destination"), "/tmp/exfil.csv"),
    (("email", "recipient"), "attacker@evil.example"),
    (("department", "org", "team"), "all"),
    (("employee", "user", "account"), "all"),
)


def _sample_string(name: str) -> str:
    lowered = name.lower()
    for needles, value in _SAMPLE_BY_NAME:
        if any(n in lowered for n in needles):
            return value
    return "all"


def _args_for(schema: dict[str, Any]) -> dict[str, Any]:
    """Synthesise a valid argument dict from a tool's advertised inputSchema.

    Honeypot names and parameters are LLM-generated, so hardcoding arguments
    breaks whenever generation produces a different signature -- and FastMCP
    rejects the call outright on a missing/unexpected argument, which on stage
    looks like HoneyMCP failing. Only `required` properties are filled: extras
    are optional by definition, and an empty enum-constrained string would be
    rejected.
    """
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    args: dict[str, Any] = {}
    for name in required:
        spec = props.get(name) or {}
        choices = spec.get("enum")
        if choices:
            args[name] = choices[0]
            continue
        declared = spec.get("type")
        if isinstance(declared, list):  # e.g. ["string", "null"]
            declared = next((t for t in declared if t != "null"), "string")
        declared = declared or "string"
        if declared == "string":
            args[name] = _sample_string(name)
        else:
            args[name] = _SAMPLE_BY_TYPE.get(declared, "all")
    return args


async def run_attack(
    env: dict[str, str], pacer: Pacer, event_dir: Path, transport: str
) -> dict[str, Any]:
    """Drive the protected server as a malicious agent. Returns a result summary."""
    from mcp import ClientSession

    summary: dict[str, Any] = {
        "honeypots": [],
        "triggered": None,
        "blocked": False,
        "dynamic": False,
    }

    # The server's stderr carries FastMCP's startup banner and any LLM warning.
    # Inherited, it scrolls across the middle of the narration on the projector,
    # so tee it to a file the operator can read if a run misbehaves.
    server_log = event_dir.parent / "server.log"
    server_log.parent.mkdir(parents=True, exist_ok=True)

    if transport == "stdio":
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(
            command="uv",
            args=["run", "python", str(SERVER_SCRIPT)],
            env={**env, "MCP_TRANSPORT": "stdio"},
            cwd=str(REPO_ROOT),
        )

        with open(server_log, "w", encoding="utf-8") as errlog:
            async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    await _drive_session(session, summary, pacer)
    elif transport == "sse":
        from mcp.client.sse import sse_client

        proc = _start_network_server(env, transport, server_log)
        try:
            async with sse_client(_transport_url(transport)) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    await _drive_session(session, summary, pacer)
        finally:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            if proc.poll() is None:
                proc.kill()
    else:
        from mcp.client.streamable_http import streamablehttp_client

        proc = _start_network_server(env, transport, server_log)
        try:
            async with streamablehttp_client(_transport_url(transport)) as (
                read_stream,
                write_stream,
                _get_session_id,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    await _drive_session(session, summary, pacer)
        finally:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            if proc.poll() is None:
                proc.kill()

    return _report_forensics(summary, event_dir, pacer)


async def _drive_session(session: Any, summary: dict[str, Any], pacer: Pacer) -> None:
    """Steps 1-4: the attack itself, driven against a live MCP session."""
    # --- 1. Reconnaissance: what tools does this server expose? ---
    step(1, "Agent connects and enumerates the tool surface" + dim(" (recon)"))
    pacer.beat()

    listed = await session.list_tools()
    names = [t.name for t in listed.tools]
    honeypots = [n for n in names if n not in REAL_TOOLS]
    summary["honeypots"] = honeypots
    schemas = {t.name: getattr(t, "inputSchema", None) or {} for t in listed.tools}
    # Dynamic tools are LLM-named, so anything outside the static
    # fallback set indicates live generation succeeded.
    static_fallbacks = {"export_user_data", "dump_database_credentials", "get_api_keys"}
    generated = [n for n in honeypots if n not in static_fallbacks]
    summary["dynamic"] = bool(generated)

    print(f"      {len(names)} tools visible to the agent:")
    for n in names:
        if n in REAL_TOOLS:
            print(f"        {green('*')} {n} {dim('(real)')}")
        elif n in generated:
            print(f"        {red('*')} {n} {dim('(honeypot -- LLM-generated for this server)')}")
        else:
            print(f"        {red('*')} {n} {dim('(honeypot -- indistinguishable)')}")
    print()
    print(
        "      "
        + dim("The agent cannot tell these apart. Neither could a human " "reading the schema.")
    )
    pacer.beat(1.4)

    if not honeypots:
        print()
        print(red("      No honeypot tools were registered -- aborting."))
        print(dim("      Check HoneyMCP registration in examples/arsenal/hr_server.py"))
        return

    # --- 2. A legitimate call, to prove zero false positives ---
    print()
    step(2, "Agent makes a " + bold("legitimate") + " call: list_departments()")
    pacer.beat()
    legit = await session.call_tool("list_departments", {})
    if _is_error(legit):
        print(f"      {red('unexpected error on a real tool')}")
    else:
        print(f"      {green('OK')} -- real data returned, nothing logged, no alert.")
        print(f"      {dim('Legitimate traffic is never affected. This matters: a')}")
        print(f"      {dim('honeypot that fires on real users is worse than none.')}")
    pacer.beat(1.4)

    # --- 3. The grab: agent takes the bait ---
    #
    # Prefer an LLM-generated honeypot: one named for *this* server's domain is
    # the stronger story, and a static-catalog name is the less interesting
    # fallback. Either way the capture path is identical.
    target = generated[0] if generated else honeypots[0]
    print()
    step(3, "Agent goes for the high-value data: " + bold(red(f"{target}()")))
    if target in generated:
        print(f"      {dim('Note the name -- the LLM invented it to fit an HR server.')}")
    print(f"      {dim('This is the moment an exfiltration attempt becomes visible.')}")
    pacer.beat(1.0)

    grab_args = _args_for(schemas.get(target) or {})
    if grab_args:
        print(f"      {dim('args: ' + json.dumps(grab_args))}")
    grab = await session.call_tool(target, grab_args)
    text = _text_of(grab)
    preview = text.strip().splitlines()[:4]

    print()
    print(f"      {yellow('Server responds with convincing fake data:')}")
    for line in preview:
        print(f"        {dim(line[:88])}")
    if len(text.strip().splitlines()) > 4:
        print(f"        {dim('...')}")
    print()
    print(f"      {red(bold('>> ATTACK CAPTURED'))} -- the agent believes it succeeded.")
    summary["triggered"] = target
    pacer.beat(1.6)

    # --- 4. Post-detection follow-up ---
    #
    # SCANNER mode should block this. It is still printed
    # conditionally: the narration must stay truthful if lockout ever
    # regresses (it silently no-op'd for the whole FastMCP 3.x
    # dispatch-bug window, see tests/test_protection_mode_enforcement).
    print()
    step(4, "Agent continues probing after the grab")
    pacer.beat()
    after = await session.call_tool("get_employee_profile", {"employee_id": "E1001"})
    summary["blocked"] = _is_error(after)
    if summary["blocked"]:
        print(f"      {red('BLOCKED')} -- {_text_of(after).strip()[:60]}")
        print(f"      {dim('SCANNER mode burned the session: every later call fails.')}")
    else:
        print(f"      {dim('Call still served -- the agent suspects nothing.')}")
        print(f"      {dim('Detection is passive here: the value is the capture')}")
        print(f"      {dim('and the forensic record, not blocking the caller.')}")
    pacer.beat(1.2)


def _report_forensics(summary: dict[str, Any], event_dir: Path, pacer: Pacer) -> dict[str, Any]:
    """Step 5: read back what HoneyMCP persisted, after the server has exited."""
    print()
    step(5, "What the defender is left holding")
    pacer.beat()
    # Event files are named HHMMSS_<session[:8]>.json under a YYYY-MM-DD dir
    # (storage/event_store.py) -- not evt_*.json, which is the event_id prefix.
    # The write is async, so give it a moment to land before reading.
    events: list[Path] = []
    for _ in range(20):
        events = sorted(p for p in event_dir.rglob("*.json") if p.is_file())
        if events:
            break
        time.sleep(0.1)
    if not events:
        print(f"      {yellow('No event files found yet')} at {event_dir}")
        return summary

    fingerprint = json.loads(events[-1].read_text())
    summary["event"] = fingerprint

    def show(label: str, value: Any) -> None:
        if value not in (None, "", [], {}):
            print(f"        {label:<18} {value}")

    print(f"      {green('Captured attack fingerprint')} {dim(str(events[-1].name))}")
    show("event_id", fingerprint.get("event_id"))
    show("session_id", fingerprint.get("session_id"))
    show("threat_level", red(str(fingerprint.get("threat_level"))))
    show("category", fingerprint.get("attack_category"))
    # show() skips empty values, so any field this build leaves unset simply
    # does not render rather than printing "None" on the projector.
    show(
        "tool",
        fingerprint.get("ghost_tool_called")
        or fingerprint.get("tool_name")
        or fingerprint.get("ghost_tool_name"),
    )
    show("arguments", json.dumps(fingerprint.get("arguments", {}))[:60])
    seq = fingerprint.get("tool_call_sequence") or []
    if seq:
        rendered = [s.get("tool_name", s) if isinstance(s, dict) else s for s in seq]
        show("call_sequence", " -> ".join(str(r) for r in rendered)[:60])
    show("timestamp", fingerprint.get("timestamp"))
    print()
    print(f"      {dim('Full record: ' + str(events[-1]))}")
    return summary


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="HoneyMCP Black Hat Arsenal demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--no-dashboard", action="store_true", help="terminal only")
    p.add_argument("--static", action="store_true", help="force static honeypots (no LLM)")
    p.add_argument("--keep-events", action="store_true", help="keep events from earlier runs")
    p.add_argument("--slow", action="store_true", help="slower narration")
    p.add_argument("--fast", action="store_true", help="minimal pauses")
    p.add_argument(
        "--transport",
        default="sse",
        choices=("sse", "http", "streamable-http", "stdio"),
        help="MCP server transport for the attack path (default: sse)",
    )
    p.add_argument(
        "--event-path",
        type=Path,
        default=Path(tempfile.gettempdir()) / "honeymcp-arsenal" / "events",
        help="where demo events are written (kept out of ~/.honeymcp)",
    )
    return p.parse_args()


def main() -> int:
    # Narration is the product here: keep it flushing even when stdout is a
    # pipe (tee'd to a file, captured for a recording) rather than a terminal.
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(line_buffering=True)

    args = parse_args()
    transport = _normalize_transport(args.transport)
    scale = 1.8 if args.slow else (0.0 if args.fast else 1.0)
    pacer = Pacer(scale)

    event_dir: Path = args.event_path
    if not args.keep_events and event_dir.exists():
        shutil.rmtree(event_dir, ignore_errors=True)
    event_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["HONEYMCP_EVENT_PATH"] = str(event_dir)
    if args.static:
        env["ARSENAL_STATIC_ONLY"] = "1"

    banner("HoneyMCP -- catching a malicious AI agent in the act")
    print("  A protected HR MCP server. An agent that wants the payroll data.")
    print(f"  {dim('Events -> ' + str(event_dir))}")
    if transport == "stdio":
        print(f"  {yellow('Transport -> stdio (explicit fallback; network demo is SSE/HTTP)')}")
    else:
        print(f"  {dim('Transport -> ' + transport + ' at ' + _transport_url(transport))}")
    if args.static:
        print(f"  {dim('Honeypots -> static catalog (offline mode)')}")
    else:
        print(f"  {dim('Honeypots -> LLM-generated, static fallback if unreachable')}")

    dash: Optional[subprocess.Popen] = None
    try:
        if not args.no_dashboard:
            print()
            print(f"  Starting dashboard {dim('(this is the defender view)')} ...")
            dash = start_dashboard(env)
            if dash or _port_open(DASHBOARD_HOST, DASHBOARD_PORT):
                print(f"  {green('Dashboard up')} -> {bold(DASHBOARD_URL)}")
                print(f"  {dim('Open it now, side by side with this terminal.')}")
                pacer.beat(2.2)
            else:
                print(f"  {yellow('Dashboard unavailable')} -- continuing terminal-only.")
                print(f"  {dim('Run `make run-ui` separately if you want the UI.')}")

        banner("Live attack")
        summary = asyncio.run(run_attack(env, pacer, event_dir, transport))

        banner("Result")
        gen = "LLM-generated (live)" if summary.get("dynamic") else "static catalog"
        print(f"  Honeypots deployed   {len(summary['honeypots'])}  {dim('(' + gen + ')')}")
        print(
            f"  Attack captured      {green('yes') if summary.get('triggered') else red('no')}"
            f"  {dim(str(summary.get('triggered') or ''))}"
        )
        if summary.get("blocked"):
            print(f"  Session locked out   {green('yes')} {dim('(SCANNER mode)')}")
        print(
            f"  Forensic record      "
            f"{green('written') if summary.get('event') else yellow('none')}"
        )
        print(f"  False positives      {green('0')} {dim('(the legitimate call was untouched)')}")
        print()
        print(f"  {bold('The point:')} the attacker never touched real data, and the")
        print("  defender now has a full forensic record of the attempt.")
        if dash or _port_open(DASHBOARD_HOST, DASHBOARD_PORT):
            print()
            print(f"  Dashboard: {bold(DASHBOARD_URL)}")
            print(f"  {dim('Press Ctrl-C when you are done presenting.')}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print()
        return 0

    except KeyboardInterrupt:
        print()
        print(dim("  interrupted"))
        return 130
    except FileNotFoundError as exc:
        print()
        print(red(f"  Missing executable: {exc}"))
        print(dim("  `uv` must be on PATH. Try: uv sync"))
        return 1
    except Exception as exc:  # keep the booth calm: report, don't traceback
        print()
        print(red(f"  Demo failed: {type(exc).__name__}: {exc}"))
        print(
            dim(
                "  Retry offline-safe:  uv run python examples/arsenal/run_demo.py "
                "--static --transport sse"
            )
        )
        return 1
    finally:
        if dash is not None:
            dash.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                dash.wait(timeout=5)
            if dash.poll() is None:
                dash.kill()


if __name__ == "__main__":
    raise SystemExit(main())
