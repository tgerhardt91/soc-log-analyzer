import { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";
import { colors } from "../theme";
import SummaryCards from "../components/SummaryCards";
import Timeline from "../components/Timeline";
import AnomalyPanel from "../components/AnomalyPanel";
import LogTable, { LogFilters, EMPTY_LOG_FILTERS } from "../components/LogTable";

type AnalysisData = {
  id: string;
  filename: string;
  status: string;
  summary: string | null;
  total_events: number;
  blocked_count: number;
  created_at: string;
  entries: unknown[];
  total_pages: number;
  current_page: number;
  total_entries: number;
  anomalies: unknown[];
  timeline: { hour: string; total: number; blocked: number }[];
};

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<AnalysisData | null>(null);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<LogFilters>(EMPTY_LOG_FILTERS);
  const [polling, setPolling] = useState(true);
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchData = useCallback(async (pg: number, f: LogFilters) => {
    try {
      const params: Record<string, string | number> = { page: pg, per_page: 100 };
      if (f.username)      params.username      = f.username;
      if (f.src_ip)        params.src_ip        = f.src_ip;
      if (f.dst_hostname)  params.dst_hostname  = f.dst_hostname;
      if (f.category)      params.category      = f.category;
      if (f.action)        params.action        = f.action;
      if (f.response_code) params.response_code = f.response_code;
      if (f.threat_name)   params.threat_name   = f.threat_name;
      const { data: res } = await api.get(`/api/analyses/${id}`, { params });
      setData(res);
      if (res.status === "done" || res.status === "error") setPolling(false);
    } catch {
      setPolling(false);
    }
  }, [id]);

  // Initial load + polling while processing
  useEffect(() => {
    fetchData(page, filters);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!polling) return;
    const interval = setInterval(() => fetchData(page, filters), 2000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [polling, fetchData]);

  function handlePageChange(p: number) {
    setPage(p);
    fetchData(p, filters);
  }

  function handleFilterChange(f: LogFilters) {
    setFilters(f);
    setPage(1);
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    debounceTimer.current = setTimeout(() => fetchData(1, f), 350);
  }

  if (!data) return <div style={styles.loading}>Loading…</div>;

  const isProcessing = data.status === "pending" || data.status === "processing";

  const timestamps = (data.entries as { timestamp: string | null }[])
    .map((e) => e.timestamp)
    .filter(Boolean) as string[];
  const timeRange = { min: timestamps[0] ?? null, max: timestamps[timestamps.length - 1] ?? null };

  return (
    <div style={styles.page}>
      <nav style={styles.nav}>
        <div style={styles.navLeft}>
          <div style={styles.logoMark}>⬡</div>
          <span style={styles.logoText}>SOC Log Analyzer</span>
          <span style={styles.navDivider} />
          <button style={styles.backBtn} onClick={() => navigate("/")}>← Upload</button>
        </div>
        <span style={styles.filename}>{data.filename}</span>
        <span style={{ ...styles.statusBadge, ...statusColor(data.status) }}>{data.status}</span>
      </nav>

      <div style={styles.content}>
        {isProcessing ? (
          <div style={styles.processingBox}>
            <div style={styles.spinnerRing} />
            <p style={styles.processingTitle}>Analyzing log file…</p>
            <p style={styles.processingText}>Parsing entries, running anomaly detection, and generating AI summary.</p>
          </div>
        ) : data.status === "error" ? (
          <div style={styles.errorBox}>
            <p style={{ margin: 0, color: colors.danger }}>Processing failed: {data.summary}</p>
          </div>
        ) : (
          <>
            <SummaryCards
              totalEvents={data.total_events ?? 0}
              blockedCount={data.blocked_count ?? 0}
              summary={data.summary}
              anomalyCount={(data.anomalies as unknown[]).length}
              timeRange={timeRange}
            />
            <Timeline data={data.timeline} />
            <AnomalyPanel anomalies={data.anomalies as Parameters<typeof AnomalyPanel>[0]["anomalies"]} />
            <LogTable
              entries={data.entries as Parameters<typeof LogTable>[0]["entries"]}
              totalPages={data.total_pages}
              currentPage={data.current_page}
              totalEntries={data.total_entries ?? data.total_events ?? 0}
              filters={filters}
              onFilterChange={handleFilterChange}
              onPageChange={handlePageChange}
            />
          </>
        )}
      </div>
    </div>
  );
}

function statusColor(status: string): React.CSSProperties {
  if (status === "done") return { background: colors.successMid, color: colors.success };
  if (status === "error") return { background: colors.dangerMid, color: colors.danger };
  return { background: colors.accentBg, color: colors.accent };
}

const styles: Record<string, React.CSSProperties> = {
  page: { minHeight: "100vh", background: colors.bgPage, fontFamily: "system-ui, sans-serif" },
  nav: {
    display: "flex", alignItems: "center", gap: 16,
    padding: "0 2rem", height: 56,
    background: colors.bgSurface,
    borderBottom: `1px solid ${colors.border}`,
  },
  navLeft: { display: "flex", alignItems: "center", gap: 10 },
  logoMark: {
    width: 24, height: 24, borderRadius: 5,
    background: `linear-gradient(135deg, ${colors.accent}, ${colors.accentDim})`,
    boxShadow: `0 0 10px ${colors.accent}55`,
    display: "flex", alignItems: "center", justifyContent: "center",
    fontSize: 12, color: colors.bgPage, fontWeight: 900,
  },
  logoText: { color: colors.textPrimary, fontWeight: 700, fontSize: 14 },
  navDivider: { display: "inline-block", width: 1, height: 16, background: colors.border, margin: "0 4px" },
  backBtn: {
    background: "transparent", border: `1px solid ${colors.border}`,
    color: colors.textMuted, padding: "5px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13,
  },
  filename: { color: colors.textPrimary, fontWeight: 600, fontSize: 15, flex: 1 },
  statusBadge: { padding: "3px 10px", borderRadius: 4, fontSize: 12, fontWeight: 700 },
  content: { maxWidth: 1280, margin: "2rem auto", padding: "0 1.5rem" },
  loading: { color: colors.textMuted, textAlign: "center", marginTop: "4rem", fontFamily: "system-ui, sans-serif" },
  processingBox: { textAlign: "center", marginTop: "5rem" },
  processingTitle: { color: colors.textPrimary, fontSize: 18, fontWeight: 600, marginTop: 24, marginBottom: 8 },
  processingText: { color: colors.textMuted, fontSize: 14 },
  spinnerRing: {
    width: 48, height: 48,
    border: `3px solid ${colors.border}`,
    borderTop: `3px solid ${colors.accent}`,
    borderRadius: "50%",
    animation: "spin 1s linear infinite",
    margin: "0 auto",
    boxShadow: `0 0 16px ${colors.accent}44`,
  },
  errorBox: {
    background: colors.dangerBg, border: `1px solid ${colors.dangerMid}`,
    borderRadius: 10, padding: "1.5rem",
  },
};
