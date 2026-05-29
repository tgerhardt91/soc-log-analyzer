import { colors } from "../theme";

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

export type LogFilters = {
  username: string;
  src_ip: string;
  dst_hostname: string;
  category: string;
  action: string;
  response_code: string;
  threat_name: string;
};

export const EMPTY_LOG_FILTERS: LogFilters = {
  username: "", src_ip: "", dst_hostname: "",
  category: "", action: "", response_code: "", threat_name: "",
};

type Props = {
  entries: Entry[];
  totalPages: number;
  currentPage: number;
  totalEntries: number;
  filters: LogFilters;
  onFilterChange: (filters: LogFilters) => void;
  onPageChange: (page: number) => void;
};

export default function LogTable({ entries, totalPages, currentPage, totalEntries, filters, onFilterChange, onPageChange }: Props) {
  const hasActiveFilter = Object.values(filters).some(Boolean);

  function setFilter(key: keyof LogFilters, value: string) {
    onFilterChange({ ...filters, [key]: value });
  }

  function clearFilters() {
    onFilterChange(EMPTY_LOG_FILTERS);
  }

  return (
    <div>
      <div style={styles.titleRow}>
        <h3 style={styles.title}>Events</h3>
        {hasActiveFilter && (
          <button style={styles.clearBtn} onClick={clearFilters}>Clear filters</button>
        )}
      </div>
      <div style={styles.tableWrap}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Timestamp</th>
              <th style={styles.th}>User</th>
              <th style={styles.th}>Source IP</th>
              <th style={styles.th}>Destination</th>
              <th style={styles.th}>Category</th>
              <th style={styles.th}>Action</th>
              <th style={styles.th}>Bytes Out</th>
              <th style={styles.th}>Code</th>
              <th style={styles.th}>Threat</th>
            </tr>
            <tr style={{ background: colors.bgElevated }}>
              <th style={styles.filterCell} />
              <th style={styles.filterCell}>
                <input style={styles.filterInput} placeholder="Filter…" value={filters.username} onChange={(e) => setFilter("username", e.target.value)} />
              </th>
              <th style={styles.filterCell}>
                <input style={styles.filterInput} placeholder="Filter…" value={filters.src_ip} onChange={(e) => setFilter("src_ip", e.target.value)} />
              </th>
              <th style={styles.filterCell}>
                <input style={styles.filterInput} placeholder="Filter…" value={filters.dst_hostname} onChange={(e) => setFilter("dst_hostname", e.target.value)} />
              </th>
              <th style={styles.filterCell}>
                <input style={styles.filterInput} placeholder="Filter…" value={filters.category} onChange={(e) => setFilter("category", e.target.value)} />
              </th>
              <th style={styles.filterCell}>
                <select style={styles.filterSelect} value={filters.action} onChange={(e) => setFilter("action", e.target.value)}>
                  <option value="">All</option>
                  <option value="Allowed">Allowed</option>
                  <option value="Blocked">Blocked</option>
                </select>
              </th>
              <th style={styles.filterCell} />
              <th style={styles.filterCell}>
                <input style={styles.filterInput} placeholder="Filter…" value={filters.response_code} onChange={(e) => setFilter("response_code", e.target.value)} />
              </th>
              <th style={styles.filterCell}>
                <input style={styles.filterInput} placeholder="Filter…" value={filters.threat_name} onChange={(e) => setFilter("threat_name", e.target.value)} />
              </th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id} style={{
                background: e.is_anomalous ? `${colors.dangerBg}CC` : "transparent",
                borderLeft: e.is_anomalous ? `2px solid ${colors.danger}66` : "2px solid transparent",
              }}>
                <td style={styles.td}>{e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</td>
                <td style={styles.td}>{e.username ?? "—"}</td>
                <td style={styles.td}>{e.src_ip ?? "—"}</td>
                <td style={{ ...styles.td, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.dst_hostname ?? ""}>
                  {e.dst_hostname ?? "—"}
                </td>
                <td style={styles.td}>{e.category ?? "—"}</td>
                <td style={styles.td}>
                  <span style={e.action?.toLowerCase() === "blocked" ? styles.blocked : styles.allowed}>
                    {e.action ?? "—"}
                  </span>
                </td>
                <td style={styles.td}>{e.bytes_sent?.toLocaleString() ?? "—"}</td>
                <td style={styles.td}>{e.response_code ?? "—"}</td>
                <td style={{ ...styles.td, color: colors.danger }}>{e.threat_name || ""}</td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr>
                <td colSpan={9} style={styles.emptyCell}>No entries match the current filters.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div style={styles.footer}>
        <span style={styles.pageInfo}>
          {hasActiveFilter ? `${totalEntries} matching entries` : `${totalEntries} entries`}
        </span>
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
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  titleRow: { display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 },
  title: { color: colors.textMuted, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" },
  clearBtn: { background: "transparent", border: `1px solid ${colors.border}`, color: colors.textMuted, padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 12 },
  tableWrap: { overflowX: "auto", borderRadius: 10, border: `1px solid ${colors.border}` },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 13 },
  th: { color: colors.textMuted, padding: "10px 12px", textAlign: "left", borderBottom: `1px solid ${colors.border}`, whiteSpace: "nowrap", background: colors.bgElevated, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.04em" },
  filterCell: { padding: "6px 8px", borderBottom: `1px solid ${colors.border}`, background: colors.bgElevated },
  filterInput: { width: "100%", background: colors.bgSurface, border: `1px solid ${colors.border}`, borderRadius: 5, color: colors.textSecondary, fontSize: 12, padding: "4px 7px", outline: "none", boxSizing: "border-box" },
  filterSelect: { width: "100%", background: colors.bgSurface, border: `1px solid ${colors.border}`, borderRadius: 5, color: colors.textSecondary, fontSize: 12, padding: "4px 7px" },
  td: { color: colors.textSecondary, padding: "9px 12px", borderBottom: `1px solid ${colors.border}` },
  allowed: { padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, background: colors.successBg, color: colors.success },
  blocked: { padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, background: colors.dangerBg, color: colors.danger },
  emptyCell: { color: colors.textMuted, padding: "2rem", textAlign: "center", fontSize: 13 },
  footer: { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12, paddingBottom: 32 },
  pagination: { display: "flex", alignItems: "center", gap: 12 },
  pageBtn: { background: colors.bgSurface, border: `1px solid ${colors.border}`, color: colors.textSecondary, padding: "6px 16px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  pageInfo: { color: colors.textMuted, fontSize: 12 },
};
