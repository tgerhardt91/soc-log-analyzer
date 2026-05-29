import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";
import SummaryCards from "../components/SummaryCards";
import Timeline from "../components/Timeline";
import AnomalyPanel from "../components/AnomalyPanel";
import LogTable from "../components/LogTable";

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
  anomalies: unknown[];
  timeline: { hour: string; total: number; blocked: number }[];
};

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<AnalysisData | null>(null);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<{ action?: string; category?: string; username?: string }>({});
  const [polling, setPolling] = useState(true);

  const fetchData = useCallback(async (pg = page, f = filters) => {
    try {
      const params: Record<string, string | number> = { page: pg, per_page: 100 };
      if (f.action) params.action = f.action;
      if (f.category) params.category = f.category;
      if (f.username) params.username = f.username;
      const { data: res } = await api.get(`/api/analyses/${id}`, { params });
      setData(res);
      if (res.status === "done" || res.status === "error") {
        setPolling(false);
      }
    } catch {
      setPolling(false);
    }
  }, [id, page, filters]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (!polling) return;
    const interval = setInterval(() => fetchData(), 2000);
    return () => clearInterval(interval);
  }, [polling, fetchData]);

  function handlePageChange(p: number) {
    setPage(p);
    fetchData(p, filters);
  }

  function handleFilter(f: { action?: string; category?: string; username?: string }) {
    setFilters(f);
    setPage(1);
    fetchData(1, f);
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
        <button style={styles.backBtn} onClick={() => navigate("/")}>← Back</button>
        <span style={styles.filename}>{data.filename}</span>
        <span style={{ ...styles.statusBadge, ...statusColor(data.status) }}>{data.status}</span>
      </nav>

      <div style={styles.content}>
        {isProcessing ? (
          <div style={styles.processingBox}>
            <div style={styles.spinner} />
            <p style={styles.processingText}>Parsing logs and running AI analysis…</p>
          </div>
        ) : data.status === "error" ? (
          <div style={styles.errorBox}>
            <p>Processing failed: {data.summary}</p>
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
              onPageChange={handlePageChange}
              onFilter={handleFilter}
            />
          </>
        )}
      </div>
    </div>
  );
}

function statusColor(status: string): React.CSSProperties {
  if (status === "done") return { background: "#166534", color: "#86efac" };
  if (status === "error") return { background: "#7f1d1d", color: "#fca5a5" };
  return { background: "#1e3a5f", color: "#93c5fd" };
}

const styles: Record<string, React.CSSProperties> = {
  page: { minHeight: "100vh", background: "#0f172a", fontFamily: "system-ui, sans-serif" },
  nav: { display: "flex", alignItems: "center", gap: 16, padding: "1rem 2rem", background: "#1e293b", borderBottom: "1px solid #334155" },
  backBtn: { background: "transparent", border: "1px solid #475569", color: "#94a3b8", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  filename: { color: "#f1f5f9", fontWeight: 600, fontSize: 16, flex: 1 },
  statusBadge: { padding: "3px 10px", borderRadius: 4, fontSize: 12, fontWeight: 700 },
  content: { maxWidth: 1200, margin: "2rem auto", padding: "0 1.5rem" },
  loading: { color: "#94a3b8", textAlign: "center", marginTop: "4rem", fontFamily: "system-ui, sans-serif" },
  processingBox: { textAlign: "center", marginTop: "4rem" },
  processingText: { color: "#94a3b8", marginTop: 16 },
  spinner: {
    width: 40, height: 40, border: "3px solid #334155", borderTop: "3px solid #3b82f6",
    borderRadius: "50%", animation: "spin 1s linear infinite", margin: "0 auto",
  },
  errorBox: { background: "#7f1d1d", borderRadius: 10, padding: "1.5rem", color: "#fca5a5" },
};
