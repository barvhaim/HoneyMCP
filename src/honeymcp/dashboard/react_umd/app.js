const { useEffect, useState, useCallback } = React;

// --- Utility Functions ---

function timeAgo(dateString) {
  const date = new Date(dateString);
  const now = new Date();
  const seconds = Math.floor((now - date) / 1000);

  let interval = seconds / 31536000;
  if (interval > 1) return Math.floor(interval) + " years ago";
  interval = seconds / 2592000;
  if (interval > 1) return Math.floor(interval) + " months ago";
  interval = seconds / 86400;
  if (interval > 1) return Math.floor(interval) + " days ago";
  interval = seconds / 3600;
  if (interval > 1) return Math.floor(interval) + " hours ago";
  interval = seconds / 60;
  if (interval > 1) return Math.floor(interval) + " minutes ago";
  return Math.floor(seconds) + " seconds ago";
}

function formatDateTime(dateString) {
  return new Date(dateString).toLocaleString(undefined, {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function buildQuery(params) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== null && value !== undefined && String(value).trim() !== "") {
      query.set(key, String(value));
    }
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

// --- Icons (SVG Components) ---

const IconActivity = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
);

const IconAlert = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
);

const IconShield = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
);

const IconTerminal = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
);

const IconChevronDown = ({ className }) => (
  <svg className={className} width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
);

// --- Components ---

function Badge({ children, type = "medium" }) {
  return (
    <span className={`badge ${type.toLowerCase()}`}>
      {children}
    </span>
  );
}

function MetricCard({ label, value, icon, loading }) {
  return (
    <div className="metric-card">
      <div className="header-top">
        <span className="metric-label">{label}</span>
        {icon && <span className="text-brand">{icon}</span>}
      </div>
      {loading ? (
        <div className="skeleton" style={{ height: '36px', width: '60%' }}></div>
      ) : (
        <div className="metric-value">{value}</div>
      )}
    </div>
  );
}

function EventRow({ event }) {
  const [expanded, setExpanded] = useState(false);
  const threatLevel = event.threat_level?.toLowerCase() || 'low';

  return (
    <div className="event-row">
      <div
        className="event-summary"
        onClick={() => setExpanded(!expanded)}
      >
        <Badge type={threatLevel}>{event.threat_level}</Badge>

        <div className="event-main">
          <div className="event-title">{event.ghost_tool_called}</div>
          <div className="event-meta">
            <span>{timeAgo(event.timestamp)}</span>
            <span>•</span>
            <span>{event.attack_category}</span>
          </div>
        </div>

        <IconChevronDown className={`chevron ${expanded ? 'rotate-180' : ''}`} />
      </div>

      {expanded && (
        <div className="event-details">
          <div className="grid detail-grid">
            <div className="detail-group">
              <div className="detail-label">Session ID</div>
              <div className="font-mono text-sm">{event.session_id}</div>
            </div>
            <div className="detail-group">
              <div className="detail-label">Full Timestamp</div>
              <div className="text-sm">{formatDateTime(event.timestamp)}</div>
            </div>
          </div>

          <div className="detail-group">
            <div className="detail-label">Tool Sequence</div>
            <div className="text-sm">
              {(event.tool_call_sequence || []).join(" → ") || "Single Call"}
            </div>
          </div>

          <div className="detail-group">
            <div className="detail-label">Arguments</div>
            <pre className="code-block">
              {JSON.stringify(event.arguments || {}, null, 2)}
            </pre>
          </div>

          {event.response_sent && (
            <div className="detail-group">
              <div className="detail-label">Response</div>
              <pre className="code-block">
                {event.response_sent}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FilterBar({ filters, options, onChange, onRefresh, onClear, loading, clearing }) {
  return (
    <section className="panel glass-panel filter-panel">
      <div className="grid filters">
        {/* API Base input removed as requested */}

        <div className="form-group">
          <label>Threat Level</label>
          <select name="threat_level" value={filters.threat_level} onChange={onChange}>
            <option value="">All Levels</option>
            {options.threat_levels.map(l => <option key={l} value={l}>{l}</option>)}
          </select>
        </div>

        <div className="form-group">
          <label>Category</label>
          <select name="category" value={filters.category} onChange={onChange}>
            <option value="">All Categories</option>
            {options.categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>

        <div className="form-group">
          <button className="primary" onClick={onRefresh} disabled={loading}>
            {loading ? "Refreshing..." : "Apply Filters"}
          </button>
        </div>

        <div className="form-group">
          <button className="danger" onClick={onClear} disabled={clearing || loading}>
            {clearing ? "Clearing..." : "Clear Stored Data"}
          </button>
        </div>
      </div>
    </section>
  );
}

// --- Main App ---

function App() {
  // State
  const [apiBase] = useState(() => {
    return window.location.protocol.startsWith('http')
      ? window.location.origin.replace(/\/$/, "")
      : "http://127.0.0.1:8001";
  });

  const [filters, setFilters] = useState({
    start_date: "",
    end_date: "",
    threat_level: "",
    category: "",
    tool: "",
  });

  const [options, setOptions] = useState({
    threat_levels: [],
    categories: [],
    tools: [],
  });

  const [data, setData] = useState({
    metrics: null,
    events: [],
    total: 0
  });

  const [loading, setLoading] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  // Data Fetching
  const fetchJson = useCallback(async (path, queryParams = {}, requestOptions = {}) => {
    const url = `${apiBase}${path}${buildQuery(queryParams)}`;
    try {
      const response = await fetch(url, requestOptions);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      throw err;
    }
  }, [apiBase]);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      // Parallel fetch
      const [filterData, metricsData, eventsResp] = await Promise.all([
        fetchJson("/filters", { start_date: filters.start_date, end_date: filters.end_date }).catch(() => null),
        fetchJson("/metrics", filters),
        fetchJson("/events", { ...filters, limit: 50, offset: 0 })
      ]);

      if (filterData) setOptions(filterData);

      setData({
        metrics: metricsData,
        events: eventsResp.events || [],
        total: eventsResp.total || 0
      });
    } catch (err) {
      console.error(err);
      setError("Unable to connect to HoneyMCP API. Ensure the server is running.");

      // Fallback for Development/Demo purposes if API fails
      // remove this block in strict production
      if (window.location.protocol === 'file:') {
        console.warn("Using mock data for local file preview");
        // ... mock data logic could go here
      }
    } finally {
      setLoading(false);
    }
  }, [fetchJson, filters]);

  // Initial Load
  useEffect(() => {
    loadData();
  }, [loadData]);


  // Handlers
  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value }));
  };

  const handleClearData = async () => {
    const shouldDelete = window.confirm("Delete all stored HoneyMCP events?");
    if (!shouldDelete) {
      return;
    }

    setClearing(true);
    setError(null);
    setNotice(null);

    try {
      const result = await fetchJson("/events", {}, { method: "DELETE" });
      setNotice(`Deleted ${result.deleted_events || 0} event(s).`);
      await loadData();
    } catch (err) {
      console.error(err);
      setError("Unable to clear stored events.");
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="container">
      <header className="header">
        <div className="header-top">
          <div>
            <p className="header-kicker">HoneyMCP Security Operations</p>
            <h1 className="title">HoneyMCP Dashboard</h1>
            <p className="subtitle">Real-time Threat Monitoring Intelligence</p>
          </div>
          <div className="status-indicator">
            <span className="live-dot" />
            <span>Live Feed</span>
          </div>
        </div>
      </header>

      <FilterBar
        filters={filters}
        options={options}
        onChange={handleFilterChange}
        onRefresh={loadData}
        onClear={handleClearData}
        loading={loading}
        clearing={clearing}
      />

      {notice && (
        <div className="panel panel-notice">
          <span>{notice}</span>
        </div>
      )}

      {error && (
        <div className="panel panel-error">
          <div className="message-row">
            <IconAlert />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Metrics Grid */}
      <section className="grid metrics metric-grid">
        <MetricCard
          label="Total Attacks"
          value={data.metrics?.total_attacks || 0}
          icon={<IconShield />}
          loading={loading && !data.metrics}
        />
        <MetricCard
          label="Last 24h"
          value={data.metrics?.attacks_last_24h || 0}
          icon={<IconActivity />}
          loading={loading && !data.metrics}
        />
        <MetricCard
          label="Critical Threats"
          value={data.metrics?.critical_threats || 0}
          icon={<IconAlert />}
          loading={loading && !data.metrics}
        />
        <MetricCard
          label="Active Sessions"
          value={data.metrics?.unique_sessions || 0}
          icon={<IconTerminal />}
          loading={loading && !data.metrics}
        />
      </section>

      {/* Events Feed */}
      <section className="events-section">
        <div className="section-head">
          <h3>Recent Events</h3>
          <span className="badge low">{data.total} Total</span>
        </div>

        <div className="event-list">
          {data.events.length === 0 && !loading ? (
            <div className="panel empty-state">
              <p>No events found for the selected timeframe.</p>
            </div>
          ) : (
            data.events.map(event => (
              <EventRow key={event.event_id} event={event} />
            ))
          )}

          {loading && data.events.length === 0 && (
            <div className="panel empty-state">
              <div className="skeleton" style={{ height: '20px', width: '200px', margin: '0 auto' }}></div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
