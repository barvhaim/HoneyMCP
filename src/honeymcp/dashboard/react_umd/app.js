const { useEffect, useState, useCallback, useRef } = React;

/* ============================================================
   HoneyMCP // Deception Console  — operations dashboard
   ============================================================ */

// --- utils ---

function timeAgo(dateString) {
  const date = new Date(dateString);
  const seconds = Math.floor((Date.now() - date) / 1000);
  if (seconds < 60) return `${Math.max(seconds, 0)}s ago`;
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

function formatDateTime(dateString) {
  return new Date(dateString).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function buildQuery(params) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== null && v !== undefined && String(v).trim() !== "") q.set(k, String(v));
  });
  const s = q.toString();
  return s ? `?${s}` : "";
}

const THREAT_COLORS = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
};
const CAT_COLORS = ["#6d7cff", "#4fbf8f", "#f0a24b", "#57b6e6", "#b18bf0", "#f26d78", "#ddc158"];

// --- icons ---

const I = {
  Shield: () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Pulse: () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Alert: () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  Node: () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="4" width="6" height="6"/><rect x="14" y="14" width="6" height="6"/><path d="M10 7h4a2 2 0 0 1 2 2v5"/></svg>,
  Chev: ({ open }) => <svg className={`chev ${open ? "open" : ""}`} width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>,
};

// --- components ---

function Stat({ label, value, icon, tone, loading }) {
  return (
    <div className={`stat ${tone === "crit" ? "is-crit" : ""} ${tone === "honey" ? "is-honey" : ""}`}>
      <div className="stat-top">
        <span className="stat-label">{label}</span>
        <span className="stat-ico">{icon}</span>
      </div>
      {loading
        ? <div className="skeleton" style={{ height: 40, width: "55%" }} />
        : <div className="stat-value">{Number(value || 0).toLocaleString()}</div>}
    </div>
  );
}

function DistroBlock({ title, data, colorFor }) {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, [, v]) => s + v, 0);
  return (
    <div className="distro-block">
      <div className="distro-title">{title}</div>
      {total === 0 ? (
        <div className="distro-empty">No data captured yet.</div>
      ) : (
        <>
          <div className="bar-track">
            {entries.map(([k, v]) => (
              <div key={k} className="bar-seg"
                style={{ flexGrow: v, background: colorFor(k, entries.findIndex(e => e[0] === k)) }}
                title={`${k}: ${v}`} />
            ))}
          </div>
          <div className="legend">
            {entries.map(([k, v], i) => (
              <div key={k} className="legend-row">
                <span className="legend-dot" style={{ background: colorFor(k, i) }} />
                <span className="legend-name">{k}</span>
                <span className="legend-val">{v}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function Capture({ event, fresh }) {
  const [open, setOpen] = useState(false);
  const level = (event.threat_level || "low").toLowerCase();
  const seq = event.tool_call_sequence || [];

  return (
    <div className={`capture rail-${level} ${fresh ? "fresh" : ""}`}>
      <div className="capture-summary" onClick={() => setOpen(o => !o)}>
        <span className={`tag-badge ${level}`}>{event.threat_level}</span>
        <div className="capture-body">
          <div className="capture-title">{event.ghost_tool_called}</div>
          <div className="capture-meta">
            <span>{event.attack_category}</span>
            <span className="sep">/</span>
            <span>sid:{String(event.session_id || "").slice(0, 12)}</span>
          </div>
        </div>
        <span className="capture-time">{timeAgo(event.timestamp)}</span>
        <I.Chev open={open} />
      </div>

      {open && (
        <div className="dossier">
          <div className="dossier-grid">
            <div className="field-block">
              <div className="field-key">session_id</div>
              <div className="field-val mono">{event.session_id || "—"}</div>
            </div>
            <div className="field-block">
              <div className="field-key">captured_at</div>
              <div className="field-val dim">{formatDateTime(event.timestamp)}</div>
            </div>
          </div>

          <div className="field-block" style={{ marginBottom: 16 }}>
            <div className="field-key">tool_call_sequence</div>
            {seq.length ? (
              <div className="seq">
                {seq.map((t, i) => (
                  <React.Fragment key={i}>
                    <span className="seq-node">{t}</span>
                    {i < seq.length - 1 && <span className="seq-arrow">→</span>}
                  </React.Fragment>
                ))}
              </div>
            ) : <div className="field-val dim">single call</div>}
          </div>

          <div className="field-block" style={{ marginBottom: event.response_sent ? 16 : 0 }}>
            <div className="field-key">arguments</div>
            <pre className="code">{JSON.stringify(event.arguments || {}, null, 2)}</pre>
          </div>

          {event.response_sent && (
            <div className="field-block">
              <div className="field-key">response_sent</div>
              <pre className="code">{typeof event.response_sent === "string"
                ? event.response_sent
                : JSON.stringify(event.response_sent, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FrameHead({ label, count }) {
  return (
    <div className="frame-head">
      <span className="tag">{label}</span>
      <span className="rule" />
      {count !== undefined && <span className="count">{count}</span>}
    </div>
  );
}

// --- app ---

function App() {
  const [apiBase] = useState(() =>
    window.location.protocol.startsWith("http")
      ? window.location.origin.replace(/\/$/, "")
      : "http://127.0.0.1:8001");

  const [filters, setFilters] = useState({ threat_level: "", category: "", tool: "" });
  const [options, setOptions] = useState({ threat_levels: [], categories: [], tools: [] });
  const [data, setData] = useState({ metrics: null, events: [], total: 0 });
  const [loading, setLoading] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [live, setLive] = useState(false);
  const [freshIds, setFreshIds] = useState(() => new Set());
  const [clock, setClock] = useState("");

  const fetchJson = useCallback(async (path, params = {}, opts = {}) => {
    const res = await fetch(`${apiBase}${path}${buildQuery(params)}`, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }, [apiBase]);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const [filterData, metricsData, eventsResp] = await Promise.all([
        fetchJson("/filters").catch(() => null),
        fetchJson("/metrics", filters),
        fetchJson("/events", { ...filters, limit: 100, offset: 0 }),
      ]);
      if (filterData) setOptions(filterData);
      setData({ metrics: metricsData, events: eventsResp.events || [], total: eventsResp.total || 0 });
    } catch (err) {
      console.error(err);
      setError("Cannot reach the HoneyMCP API. Is the server running?");
    } finally {
      setLoading(false);
    }
  }, [fetchJson, filters]);

  useEffect(() => { loadData(); }, [loadData]);

  // live tick clock (UTC-style HUD)
  useEffect(() => {
    const t = setInterval(() => {
      setClock(new Date().toLocaleTimeString(undefined, { hour12: false }));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  // SSE live feed — the server emits NAMED "attack" events, so we must
  // listen for that type explicitly (onmessage only catches unnamed events).
  // History is replayed on connect, so dedup by event_id.
  useEffect(() => {
    let es;
    const ingest = (msg) => {
      let evt;
      try { evt = JSON.parse(msg.data); } catch { return; }
      if (!evt || !evt.event_id) return;
      let isNew = false;
      setData(prev => {
        if (prev.events.some(e => e.event_id === evt.event_id)) return prev;
        isNew = true;
        return { ...prev, events: [evt, ...prev.events].slice(0, 100), total: prev.total + 1 };
      });
      if (!isNew) return;
      setFreshIds(prev => new Set(prev).add(evt.event_id));
      setTimeout(() => setFreshIds(prev => {
        const n = new Set(prev); n.delete(evt.event_id); return n;
      }), 1500);
    };
    try {
      es = new EventSource(`${apiBase}/stream`);
      es.onopen = () => setLive(true);
      es.onerror = () => setLive(false);
      es.addEventListener("attack", ingest);
      es.onmessage = ingest; // fallback for unnamed frames
    } catch (e) {
      setLive(false);
    }
    return () => { if (es) es.close(); };
  }, [apiBase]);

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value }));
  };

  const handleClear = async () => {
    if (!window.confirm("Purge all stored HoneyMCP captures? This cannot be undone.")) return;
    setClearing(true); setError(null); setNotice(null);
    try {
      const result = await fetchJson("/events", {}, { method: "DELETE" });
      setNotice(`Purged ${result.deleted_events || 0} capture(s).`);
      await loadData();
    } catch (err) {
      console.error(err);
      setError("Unable to purge stored captures.");
    } finally {
      setClearing(false);
    }
  };

  const m = data.metrics;

  return (
    <div className="container">
      <header className="masthead">
        <div className="brand-mark">
          <span className="brand-logo"><I.Shield /></span>
          <div className="brand-text">
            <span className="brand-glyph">Honey<span className="hl">MCP</span></span>
            <span className="brand-sub">Deception console — MCP intrusion &amp; exfiltration monitoring</span>
          </div>
        </div>
        <div className="status-cluster">
          <span className={`link-status ${live ? "online" : "offline"}`}>
            <span className="beacon" />
            {live ? "Live" : "Polling"}
          </span>
          <span className="clock">{clock}</span>
        </div>
      </header>

      {/* filters / console */}
      <FrameHead label="Filters" />
      <section className="console">
        <div className="console-grid">
          <div className="field">
            <label htmlFor="f-threat">threat level</label>
            <select id="f-threat" name="threat_level" value={filters.threat_level} onChange={handleFilterChange}>
              <option value="">all levels</option>
              {options.threat_levels.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-category">attack category</label>
            <select id="f-category" name="category" value={filters.category} onChange={handleFilterChange}>
              <option value="">all categories</option>
              {options.categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div className="field">
            <button className="primary" onClick={loadData} disabled={loading}>
              {loading ? "Loading…" : "Apply filters"}
            </button>
          </div>
          <div className="field">
            <button className="ghost" onClick={handleClear} disabled={clearing || loading}>
              {clearing ? "Purging…" : "Purge data"}
            </button>
          </div>
        </div>
      </section>

      {notice && <div className="notice ok"><I.Shield /><span>{notice}</span></div>}
      {error && <div className="notice err"><I.Alert /><span>{error}</span></div>}

      {/* telemetry */}
      <FrameHead label="Overview" />
      <section className="telemetry">
        <Stat label="total captures" value={m?.total_attacks} icon={<I.Shield />} loading={loading && !m} />
        <Stat label="last 24h" value={m?.attacks_last_24h} icon={<I.Pulse />} tone="honey" loading={loading && !m} />
        <Stat label="critical" value={m?.critical_threats} icon={<I.Alert />} tone="crit" loading={loading && !m} />
        <Stat label="unique sessions" value={m?.unique_sessions} icon={<I.Node />} loading={loading && !m} />
      </section>

      {/* distribution */}
      <FrameHead label="Distribution" />
      <section className="distro">
        <DistroBlock
          title="By threat level"
          data={m?.by_threat_level}
          colorFor={(k) => THREAT_COLORS[k.toLowerCase()] || "var(--text-4)"}
        />
        <DistroBlock
          title="By attack category"
          data={m?.by_category}
          colorFor={(k, i) => CAT_COLORS[i % CAT_COLORS.length]}
        />
      </section>

      {/* feed */}
      <FrameHead label="Intrusion feed" count={`${data.total} captured`} />
      <section className="feed">
        {data.events.length === 0 && !loading ? (
          <div className="empty">
            <span className="big">No intrusions detected</span>
            Traps are armed. Nothing has tripped a ghost tool for this query.
          </div>
        ) : (
          data.events.map(evt => (
            <Capture key={evt.event_id} event={evt} fresh={freshIds.has(evt.event_id)} />
          ))
        )}
        {loading && data.events.length === 0 && (
          <div className="empty"><div className="skeleton" style={{ height: 18, width: 220, margin: "0 auto" }} /></div>
        )}
      </section>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
