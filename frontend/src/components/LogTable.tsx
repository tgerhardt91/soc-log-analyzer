import { useState } from "react";

type Entry = {
  id: string;
  timestamp: string | null;
  username: string | null;
  src_ip: string | null;
  dst_hostname: string | null;
  category: string | null;
  action: string | null;
  bytes_sent: number;
  bytes_received: number;
  http_method: string | null;
  response_code: number | null;
  threat_name: string | null;
  is_anomalous: boolean;
};

type Props = {
  entries: Entry[];
  totalPages: number;
  currentPage: number;
  onPageChange: (page: number) => void;
  onFilter: (filters: { action?: string; category?: string; username?: string }) => void;
};

export default function LogTable({ entries, totalPages, currentPage, onPageChange, onFilter }: Props) {
  const [actionFilter, setActionFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");

  function applyFilters() {
    onFilter({ action: actionFilter || undefined, category: categoryFilter || undefined, username: userFilter || undefined });
  }

  function clearFilters() {
    setActionFilter("");
    setCategoryFilter("");
    setUserFilter("");
    onFilter({});
  }

  return (
    <div>
      <h3 style={styles.title}>Events</h3>
      <div style={styles.filters}>
        <select style={styles.select} value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
          <option value="">All Actions</option>
          <option value="Allowed">Allowed</option>
          <option value="Blocked">Blocked</option>
        </select>
        <input style={styles.filterInput} placeholder="Category…" value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} />
        <input style={styles.filterInput} placeholder="Username…" value={userFilter} onChange={(e) => setUserFilter(e.target.value)} />
        <button style={styles.applyBtn} onClick={applyFilters}>Apply</button>
        <button style={styles.clearBtn} onClick={clearFilters}>Clear</button>
      </div>
      <div style={styles.tableWrap}>
        <table style={styles.table}>
          <thead>
            <tr>
              {["Timestamp", "User", "Source IP", "Destination", "Category", "Action", "Bytes Out", "Code", "Threat"].map((h) => (
                <th key={h} style={styles.th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id} style={{ background: e.is_anomalous ? "#2d1515" : "transparent" }}>
                <td style={styles.td}>{e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</td>
                <td style={styles.td}>{e.username ?? "—"}</td>
                <td style={styles.td}>{e.src_ip ?? "—"}</td>
                <td style={{ ...styles.td, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.dst_hostname ?? ""}>
                  {e.dst_hostname ?? "—"}
                </td>
                <td style={styles.td}>{e.category ?? "—"}</td>
                <td style={styles.td}>
                  <span style={{ ...styles.actionBadge, ...(e.action?.toLowerCase() === "blocked" ? styles.blocked : styles.allowed) }}>
                    {e.action ?? "—"}
                  </span>
                </td>
                <td style={styles.td}>{e.bytes_sent?.toLocaleString() ?? "—"}</td>
                <td style={styles.td}>{e.response_code ?? "—"}</td>
                <td style={{ ...styles.td, color: "#f87171" }}>{e.threat_name || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {totalPages > 1 && (
        <div style={styles.pagination}>
          <button style={styles.pageBtn} disabled={currentPage === 1} onClick={() => onPageChange(currentPage - 1)}>
            Previous
          </button>
          <span style={styles.pageInfo}>Page {currentPage} of {totalPages}</span>
          <button style={styles.pageBtn} disabled={currentPage === totalPages} onClick={() => onPageChange(currentPage + 1)}>
            Next
          </button>
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  title: { color: "#94a3b8", fontSize: 13, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 },
  filters: { display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" },
  select: { background: "#1e293b", border: "1px solid #334155", color: "#cbd5e1", padding: "6px 10px", borderRadius: 6, fontSize: 13 },
  filterInput: { background: "#1e293b", border: "1px solid #334155", color: "#cbd5e1", padding: "6px 10px", borderRadius: 6, fontSize: 13, width: 140 },
  applyBtn: { background: "#3b82f6", border: "none", color: "#fff", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  clearBtn: { background: "transparent", border: "1px solid #334155", color: "#94a3b8", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  tableWrap: { overflowX: "auto", borderRadius: 10, border: "1px solid #1e293b" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 13 },
  th: { color: "#64748b", padding: "10px 12px", textAlign: "left", borderBottom: "1px solid #1e293b", whiteSpace: "nowrap", background: "#1e293b", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.04em" },
  td: { color: "#cbd5e1", padding: "9px 12px", borderBottom: "1px solid #0f172a" },
  actionBadge: { padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700 },
  allowed: { background: "#14532d", color: "#86efac" },
  blocked: { background: "#7f1d1d", color: "#fca5a5" },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 16, marginTop: 16 },
  pageBtn: { background: "#1e293b", border: "1px solid #334155", color: "#cbd5e1", padding: "6px 16px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  pageInfo: { color: "#64748b", fontSize: 13 },
};
