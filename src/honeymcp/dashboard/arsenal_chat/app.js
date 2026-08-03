const { useEffect, useMemo, useRef, useState } = React;

const PHASES = [
  ["recon", "Recon"],
  ["legitimate_call", "Benign call"],
  ["honeypot_trigger", "Exfil attempt"],
  ["capture", "Capture"],
  ["followup", "Lockout"],
  ["forensics", "Forensics"],
  ["result", "Result"],
];

const ROLE_LABELS = {
  agent: "HR Agent",
  mcp: "HR MCP Server",
  honeymcp: "HoneyMCP",
  narrator: "Presenter",
};

function compactJson(value) {
  if (!value || Object.keys(value).length === 0) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function normalizeAttack(evt) {
  return {
    id: `attack_${evt.event_id}`,
    timestamp: evt.timestamp,
    phase: "capture",
    role: "honeymcp",
    kind: "capture",
    title: "AttackFingerprint captured",
    body: "HoneyMCP persisted the authoritative forensic record for this ghost-tool call.",
    metadata: {
      event_id: evt.event_id,
      session_id: evt.session_id,
      tool: evt.ghost_tool_called || evt.ghost_tool,
      arguments: evt.arguments || {},
      threat_level: evt.threat_level,
      attack_category: evt.attack_category,
      response_preview: evt.response_sent,
      tool_call_sequence: evt.tool_call_sequence || [],
    },
  };
}

function RolePill({ role }) {
  return <span className={`role-pill ${role}`}>{ROLE_LABELS[role] || role}</span>;
}

function Message({ msg }) {
  const meta = msg.metadata || {};
  const hasDetails = Boolean(
    meta.tool || meta.event_id || meta.session_id || meta.arguments || meta.response_preview
  );
  return (
    <article className={`message ${msg.role || "narrator"} ${msg.kind || "message"}`}>
      <div className="message-head">
        <RolePill role={msg.role || "narrator"} />
        <span className="message-title">{msg.title}</span>
        <span className="message-time">
          {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString([], { hour12: false }) : ""}
        </span>
      </div>
      <div className="message-body">{msg.body}</div>
      {hasDetails && (
        <div className="details">
          {meta.tool && <div><b>tool</b><code>{meta.tool}</code></div>}
          {meta.threat_level && <div><b>threat</b><code>{meta.threat_level}</code></div>}
          {meta.event_id && <div><b>event</b><code>{meta.event_id}</code></div>}
          {meta.session_id && <div><b>session</b><code>{meta.session_id}</code></div>}
          {meta.arguments && Object.keys(meta.arguments).length > 0 && (
            <pre>{compactJson(meta.arguments)}</pre>
          )}
          {meta.response_preview && (
            <pre>{String(meta.response_preview).slice(0, 900)}</pre>
          )}
          {meta.tool_call_sequence && meta.tool_call_sequence.length > 0 && (
            <div className="sequence">{meta.tool_call_sequence.join(" -> ")}</div>
          )}
        </div>
      )}
    </article>
  );
}

function PhaseRail({ messages }) {
  const reached = new Set(messages.map(m => m.phase));
  let latestIndex = -1;
  messages.forEach(m => {
    const idx = PHASES.findIndex(([id]) => id === m.phase);
    if (idx > latestIndex) latestIndex = idx;
  });
  return (
    <aside className="rail">
      <div className="rail-title">Live Flow</div>
      {PHASES.map(([id, label], index) => (
        <div key={id} className={`phase ${reached.has(id) ? "done" : ""} ${index === latestIndex ? "active" : ""}`}>
          <span className="phase-dot" />
          <span>{label}</span>
        </div>
      ))}
    </aside>
  );
}

function App() {
  const [messages, setMessages] = useState([]);
  const [live, setLive] = useState(false);
  const [error, setError] = useState("");
  const seen = useRef(new Set());
  const scrollRef = useRef(null);

  const addMessage = (msg) => {
    if (!msg || !msg.id || seen.current.has(msg.id)) return;
    seen.current.add(msg.id);
    setMessages(prev => [...prev, msg].slice(-120));
  };

  useEffect(() => {
    const origin = window.location.protocol.startsWith("http")
      ? window.location.origin.replace(/\/$/, "")
      : "http://127.0.0.1:8001";
    let es;
    try {
      es = new EventSource(`${origin}/stream?event_types=demo_chat,attack&send_history=true`);
      es.onopen = () => {
        setLive(true);
        setError("");
      };
      es.onerror = () => {
        setLive(false);
        setError("Waiting for HoneyMCP stream...");
      };
      es.addEventListener("demo_chat", (msg) => {
        try { addMessage(JSON.parse(msg.data)); } catch {}
      });
      es.addEventListener("attack", (msg) => {
        try { addMessage(normalizeAttack(JSON.parse(msg.data))); } catch {}
      });
    } catch {
      setLive(false);
      setError("Unable to open the HoneyMCP stream.");
    }
    return () => { if (es) es.close(); };
  }, []);

  useEffect(() => {
    window.requestAnimationFrame(() => {
      window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" });
    });
  }, [messages]);

  const status = useMemo(() => {
    const last = messages[messages.length - 1];
    const meta = last?.metadata || {};
    return {
      tool: meta.tool || "waiting",
      session: meta.session_id || meta.opencode_session || "pending",
      model: meta.model || "OpenCode",
    };
  }, [messages]);

  return (
    <main className="stage">
      <section className="transcript-shell">
        <header className="topbar">
          <div>
            <div className="eyebrow">Black Hat Arsenal Live Demo</div>
            <h1>HR Agent Chat</h1>
          </div>
          <div className={`live ${live ? "on" : "off"}`}>
            <span />
            {live ? "Live stream" : "Reconnecting"}
          </div>
        </header>

        <div className="status-strip">
          <div><b>agent</b><span>{status.model}</span></div>
          <div><b>last tool</b><span>{status.tool}</span></div>
          <div><b>session</b><span>{status.session}</span></div>
        </div>

        <div ref={scrollRef} className="transcript">
          {messages.length === 0 ? (
            <div className="empty">
              <span>Waiting for the HR agent...</span>
              Start `examples/arsenal/run_demo.py` and keep this page open.
            </div>
          ) : messages.map(msg => <Message key={msg.id} msg={msg} />)}
          {error && <div className="stream-note">{error}</div>}
        </div>
      </section>

      <PhaseRail messages={messages} />
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
