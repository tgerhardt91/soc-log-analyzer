import { useState, useRef, DragEvent, ChangeEvent, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import { colors } from "../theme";

type Analysis = { id: string; filename: string; status: string; created_at: string };

type AnomalyTypeDef = {
  id: string;
  label: string;
  group: "rule" | "behavioral";
  description: string;
};

type PreviewEntry = {
  timestamp: string;
  username: string;
  src_ip: string;
  dst_hostname: string;
  category: string;
  action: string;
  method: string;
  bytes_sent: number;
  bytes_received: number;
  response_code: number;
  user_agent: string;
  threat_name: string;
  anomaly_type: string | null;
};

type PreviewData = {
  total_entries: number;
  seeded_counts: Record<string, number>;
  entries: PreviewEntry[];
};

const ANOMALY_TYPES: AnomalyTypeDef[] = [
  { id: "ip_spike",         group: "rule", label: "IP Spike",          description: "One IP makes 60+ requests in under 5 minutes — consistent with automated scanning or bot activity." },
  { id: "data_exfil",       group: "rule", label: "Data Exfiltration",  description: "A single request sends more than 25 MB outbound to an unknown host — a potential large-file exfiltration." },
  { id: "off_hours",        group: "rule", label: "Off-Hours Access",   description: "Network activity occurring between 11 PM and 5 AM outside normal business hours." },
  { id: "blocked_threat",   group: "rule", label: "Blocked Threat",     description: "A request blocked by ZScaler with an identified malware or threat signature attached." },
  { id: "rare_destination", group: "rule", label: "Rare Destination",   description: "A single request to an unknown-category domain not seen anywhere else in the log." },
  { id: "beaconing",        group: "behavioral",   label: "Beaconing",          description: "Regular-interval requests to the same host — a pattern consistent with C2 check-ins that rules can't express." },
  { id: "slow_exfil",       group: "behavioral",   label: "Slow Exfiltration",  description: "Many medium-sized transfers that individually stay under thresholds but exceed 50 MB cumulatively." },
  { id: "ua_anomaly",       group: "behavioral",   label: "UA Anomaly",         description: "Requests using programmatic clients (curl, python-requests) instead of standard browser user agents." },
  { id: "auth_abuse",       group: "behavioral",   label: "Auth Abuse",         description: "An IP with 70%+ authentication failures across multiple destinations — consistent with credential stuffing." },
];

const TYPE_LABEL: Record<string, string> = Object.fromEntries(ANOMALY_TYPES.map(t => [t.id, t.label]));
const RULE_TYPES = ANOMALY_TYPES.filter(t => t.group === "rule");
const AI_TYPES   = ANOMALY_TYPES.filter(t => t.group === "behavioral");
const BEHAVIORAL_TYPE_IDS = new Set(AI_TYPES.map(t => t.id));

function typeRowBg(t: string): string {
  if (t === "blocked_threat" || t === "auth_abuse") return `${colors.dangerBg}CC`;
  if (t === "data_exfil") return "#2C1008CC";
  if (t === "ip_spike") return `${colors.warningBg}CC`;
  if (t === "off_hours") return `${colors.accentBg}CC`;
  if (BEHAVIORAL_TYPE_IDS.has(t)) return "#1B0E3ACC";
  return `${colors.bgElevated}CC`;
}

function typeBadgeStyle(t: string): React.CSSProperties {
  if (t === "blocked_threat" || t === "auth_abuse") return { background: colors.dangerBg, color: colors.danger, border: `1px solid ${colors.dangerMid}` };
  if (t === "data_exfil") return { background: "#2C1008", color: "#FB923C", border: "1px solid #7C2D12" };
  if (t === "ip_spike") return { background: colors.warningBg, color: colors.warning, border: "1px solid #713F12" };
  if (t === "off_hours") return { background: colors.accentBg, color: colors.accent, border: `1px solid ${colors.accent}44` };
  if (BEHAVIORAL_TYPE_IDS.has(t)) return { background: "#1B0E3A", color: "#A78BFA", border: "1px solid #4C1D95" };
  return { background: colors.bgElevated, color: colors.textSecondary, border: `1px solid ${colors.border}` };
}

export default function UploadPage() {
  const [dragging, setDragging]       = useState(false);
  const [uploading, setUploading]     = useState(false);
  const [error, setError]             = useState("");
  const [history, setHistory]         = useState<Analysis[]>([]);
  const [selected, setSelected]       = useState<Set<string>>(new Set(ANOMALY_TYPES.map(t => t.id)));
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [importing, setImporting]     = useState(false);
  const [preview, setPreview]         = useState<PreviewData | null>(null);
  const [hoveredType, setHoveredType] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api.get("/api/analyses").then((r) => setHistory(r.data)).catch(() => {});
  }, []);

  async function upload(file: File) {
    setError("");
    setUploading(true);
    try {
      const form = new FormData();
      form.append("file", file);
      const { data } = await api.post("/api/upload", form);
      navigate(`/analysis/${data.analysis_id}`);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg ?? "Upload failed.");
    } finally {
      setUploading(false);
    }
  }

  async function loadPreview() {
    setError("");
    setLoadingPreview(true);
    try {
      const { data } = await api.post("/api/preview-sample", { anomaly_types: Array.from(selected) });
      setPreview(data);
    } catch {
      setError("Failed to generate preview.");
    } finally {
      setLoadingPreview(false);
    }
  }

  async function importAndAnalyze() {
    setImporting(true);
    try {
      const { data } = await api.post("/api/generate-sample", { anomaly_types: Array.from(selected) });
      navigate(`/analysis/${data.analysis_id}`);
    } catch {
      setError("Failed to start analysis.");
      setImporting(false);
    }
  }

  function toggleType(id: string) {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) upload(file);
  }

  function onChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) upload(file);
  }

  function logout() {
    localStorage.removeItem("token");
    navigate("/login");
  }

  return (
    <div style={styles.page}>
      <nav style={styles.nav}>
        <div style={styles.navBrand}>
          <div style={styles.logoMark}>🔍</div>
          <span style={styles.logoText}>SOC Log Analyzer</span>
        </div>
        <button style={styles.logoutBtn} onClick={logout}>Sign out</button>
      </nav>

      <div style={styles.content}>
        <h2 style={styles.heading}>Upload Log File</h2>
        <p style={styles.hint}>Accepted formats: .log, .txt, .csv &mdash; ZScaler Web Proxy</p>

        <div
          style={{
            ...styles.dropzone,
            borderColor: dragging ? colors.accent : colors.border,
            background: dragging ? colors.accentBg : colors.bgSurface,
            boxShadow: dragging ? `0 0 24px ${colors.accent}33` : "none",
          }}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input ref={inputRef} type="file" accept=".log,.txt,.csv" style={{ display: "none" }} onChange={onChange} />
          <div style={styles.uploadIcon}>↑</div>
          {uploading
            ? <p style={styles.dropText}>Uploading and processing…</p>
            : <><p style={styles.dropText}>Drop your log file here</p><p style={styles.dropSub}>or click to browse</p></>
          }
        </div>

        {error && <p style={styles.error}>{error}</p>}

        <div style={styles.divider}>
          <div style={styles.dividerLine} />
          <span style={styles.dividerText}>or generate a test file</span>
          <div style={styles.dividerLine} />
        </div>

        <div style={styles.genCard}>
          <TypeGroup label="Rule-Based Detection" types={RULE_TYPES} selected={selected} hoveredType={hoveredType} onToggle={toggleType} onHover={setHoveredType} />
          <TypeGroup label="Behavioral Detection" types={AI_TYPES} selected={selected} hoveredType={hoveredType} onToggle={toggleType} onHover={setHoveredType} accentColor="#A78BFA" />
          <div style={styles.genFooter}>
            <span style={styles.genCount}>{selected.size} of {ANOMALY_TYPES.length} anomaly types selected</span>
            <div style={{ display: "flex", gap: 8 }}>
              <button style={styles.selectAllBtn} onClick={() => setSelected(new Set(ANOMALY_TYPES.map(t => t.id)))}>Select all</button>
              <button style={styles.selectAllBtn} onClick={() => setSelected(new Set())}>Deselect all</button>
              <button
                style={{ ...styles.generateBtn, opacity: loadingPreview || selected.size === 0 ? 0.5 : 1 }}
                disabled={loadingPreview || selected.size === 0}
                onClick={loadPreview}
              >
                {loadingPreview ? "Loading preview…" : "Preview & Import"}
              </button>
            </div>
          </div>
        </div>

        {history.length > 0 && (
          <div style={styles.historyBox}>
            <h3 style={styles.historyTitle}>Previous Uploads</h3>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>File</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Uploaded</th>
                  <th style={styles.th}></th>
                </tr>
              </thead>
              <tbody>
                {history.map((a) => (
                  <tr key={a.id} style={styles.tr}>
                    <td style={styles.td}>{a.filename}</td>
                    <td style={styles.td}><span style={{ ...styles.badge, ...statusColor(a.status) }}>{a.status}</span></td>
                    <td style={styles.td}>{new Date(a.created_at).toLocaleString()}</td>
                    <td style={styles.td}>
                      {a.status === "done" && (
                        <button style={styles.viewBtn} onClick={() => navigate(`/analysis/${a.id}`)}>View</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {preview && (
        <PreviewModal
          preview={preview}
          importing={importing}
          onImport={importAndAnalyze}
          onClose={() => setPreview(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Preview modal
// ---------------------------------------------------------------------------

function PreviewModal({ preview, importing, onImport, onClose }: {
  preview: PreviewData;
  importing: boolean;
  onImport: () => void;
  onClose: () => void;
}) {
  const [filterType, setFilterType] = useState<string | null>(null);
  const seededTotal = Object.values(preview.seeded_counts).reduce((s, n) => s + n, 0);
  const visibleEntries = filterType
    ? preview.entries.filter(e => e.anomaly_type === filterType)
    : preview.entries;

  return (
    <div style={modal.overlay} onClick={onClose}>
      <div style={modal.box} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={modal.header}>
          <div>
            <div style={modal.title}>Generated Log Preview</div>
            <div style={modal.subtitle}>
              {filterType
                ? `Showing ${visibleEntries.length} entries for "${TYPE_LABEL[filterType] ?? filterType}" — click chip again to clear`
                : `${preview.total_entries.toLocaleString()} entries — ${seededTotal} seeded across ${Object.keys(preview.seeded_counts).length} anomaly type${Object.keys(preview.seeded_counts).length !== 1 ? "s" : ""}`
              }
            </div>
          </div>
          <button style={modal.closeBtn} onClick={onClose}>✕</button>
        </div>

        {/* Anomaly type summary chips — clickable to filter */}
        <div style={modal.chips}>
          {Object.entries(preview.seeded_counts).map(([type, count]) => {
            const active = filterType === type;
            return (
              <span
                key={type}
                onClick={() => setFilterType(active ? null : type)}
                style={{
                  ...modal.chip,
                  ...typeBadgeStyle(type),
                  cursor: "pointer",
                  opacity: filterType && !active ? 0.4 : 1,
                  outline: active ? `2px solid ${typeBadgeStyle(type).color as string}` : "none",
                  outlineOffset: 2,
                }}
              >
                {TYPE_LABEL[type] ?? type.replace(/_/g, " ")} · {count}
              </span>
            );
          })}
        </div>

        {/* Scrollable table */}
        <div style={modal.tableWrap}>
          <table style={{ ...modal.table, minWidth: 1200 }}>
            <thead>
              <tr>
                <th style={modal.th}>Timestamp</th>
                <th style={modal.th}>User</th>
                <th style={modal.th}>Source IP</th>
                <th style={modal.th}>Destination</th>
                <th style={modal.th}>Method</th>
                <th style={modal.th}>Category</th>
                <th style={modal.th}>Action</th>
                <th style={modal.th}>Status</th>
                <th style={modal.th}>Bytes Out</th>
                <th style={modal.th}>Bytes In</th>
                <th style={modal.th}>User Agent</th>
                <th style={modal.th}>Threat</th>
                <th style={modal.th}>Seeded Anomaly</th>
              </tr>
            </thead>
            <tbody>
              {visibleEntries.map((e, i) => (
                <tr key={i} style={{
                  background: e.anomaly_type ? typeRowBg(e.anomaly_type) : "transparent",
                  borderLeft: e.anomaly_type ? `2px solid ${typeBadgeStyle(e.anomaly_type).color as string}44` : "2px solid transparent",
                }}>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>{e.timestamp}</td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>{e.username || "—"}</td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>{e.src_ip}</td>
                  <td style={{ ...modal.td, maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.dst_hostname}>{e.dst_hostname}</td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>
                    <span style={e.method === "POST" ? modal.methodPost : modal.methodGet}>{e.method || "—"}</span>
                  </td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>{e.category || "—"}</td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>
                    <span style={e.action?.toLowerCase() === "blocked" ? modal.blocked : modal.allowed}>{e.action || "—"}</span>
                  </td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>
                    <span style={e.response_code >= 400 ? modal.statusBad : modal.statusOk}>{e.response_code || "—"}</span>
                  </td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap", textAlign: "right" }}>{e.bytes_sent > 0 ? e.bytes_sent.toLocaleString() : "—"}</td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap", textAlign: "right" }}>{e.bytes_received > 0 ? e.bytes_received.toLocaleString() : "—"}</td>
                  <td style={{ ...modal.td, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.user_agent}>{e.user_agent || "—"}</td>
                  <td style={{ ...modal.td, whiteSpace: "nowrap" }}>{e.threat_name || "—"}</td>
                  <td style={modal.td}>
                    {e.anomaly_type && (
                      <span style={{ ...modal.typeBadge, ...typeBadgeStyle(e.anomaly_type) }}>
                        {TYPE_LABEL[e.anomaly_type] ?? e.anomaly_type.replace(/_/g, " ")}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div style={modal.footer}>
          <span style={modal.footerNote}>Highlighted rows are seeded anomaly entries. Background traffic is shown without highlighting.</span>
          <div style={{ display: "flex", gap: 10 }}>
            <button style={modal.cancelBtn} onClick={onClose}>Cancel</button>
            <button
              style={{ ...modal.importBtn, opacity: importing ? 0.6 : 1 }}
              disabled={importing}
              onClick={onImport}
            >
              {importing ? "Starting analysis…" : "Import & Analyze"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TypeGroup (checkbox grid with tooltips)
// ---------------------------------------------------------------------------

type TypeGroupProps = {
  label: string;
  types: AnomalyTypeDef[];
  selected: Set<string>;
  hoveredType: string | null;
  onToggle: (id: string) => void;
  onHover: (id: string | null) => void;
  accentColor?: string;
};

function TypeGroup({ label, types, selected, hoveredType, onToggle, onHover, accentColor = colors.accent }: TypeGroupProps) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ color: accentColor, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 10 }}>
        {label}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px 24px" }}>
        {types.map(t => (
          <label key={t.id} style={{ display: "flex", alignItems: "center", gap: 7, cursor: "pointer", userSelect: "none" }}>
            <input
              type="checkbox"
              checked={selected.has(t.id)}
              onChange={() => onToggle(t.id)}
              style={{ accentColor, cursor: "pointer", width: 14, height: 14 }}
            />
            <span style={{ color: colors.textSecondary, fontSize: 13 }}>{t.label}</span>
            <div
              style={{ position: "relative", display: "inline-flex", alignItems: "center" }}
              onMouseEnter={() => onHover(t.id)}
              onMouseLeave={() => onHover(null)}
            >
              <span style={{ color: colors.textMuted, fontSize: 11, cursor: "default", lineHeight: 1 }}>ⓘ</span>
              {hoveredType === t.id && (
                <div style={{
                  position: "absolute", bottom: "calc(100% + 8px)", left: "50%",
                  transform: "translateX(-50%)",
                  background: colors.bgElevated, border: `1px solid ${colors.border}`,
                  borderRadius: 8, padding: "10px 12px", fontSize: 12,
                  color: colors.textSecondary, width: 220, zIndex: 100,
                  lineHeight: 1.5, whiteSpace: "normal", pointerEvents: "none",
                  boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
                }}>
                  {t.description}
                </div>
              )}
            </div>
          </label>
        ))}
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
  nav: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0 2rem", height: 56, background: colors.bgSurface, borderBottom: `1px solid ${colors.border}`, boxShadow: `0 1px 0 ${colors.border}` },
  navBrand: { display: "flex", alignItems: "center", gap: 10 },
  logoMark: { width: 24, height: 24, borderRadius: 5, background: `linear-gradient(135deg, ${colors.accent}, ${colors.accentDim})`, boxShadow: `0 0 10px ${colors.accent}55`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, color: colors.bgPage, fontWeight: 900 },
  logoText: { color: colors.textPrimary, fontWeight: 700, fontSize: 14 },
  logoutBtn: { background: "transparent", border: `1px solid ${colors.border}`, color: colors.textMuted, padding: "5px 14px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  content: { maxWidth: 720, margin: "2.5rem auto", padding: "0 1rem" },
  heading: { color: colors.textPrimary, marginBottom: 4, fontSize: 22 },
  hint: { color: colors.textMuted, fontSize: 13, marginBottom: 24 },
  dropzone: { border: "2px dashed", borderRadius: 12, padding: "3rem 2rem", textAlign: "center", cursor: "pointer", transition: "all 0.2s" },
  uploadIcon: { fontSize: 28, color: colors.accent, marginBottom: 12, textShadow: `0 0 12px ${colors.accent}88` },
  dropText: { color: colors.textSecondary, fontSize: 16, margin: "0 0 4px" },
  dropSub: { color: colors.textMuted, fontSize: 13, margin: 0 },
  error: { color: colors.danger, fontSize: 13, marginTop: 12 },
  divider: { display: "flex", alignItems: "center", gap: 12, margin: "28px 0 24px" },
  dividerLine: { flex: 1, height: 1, background: colors.border },
  dividerText: { color: colors.textMuted, fontSize: 12, whiteSpace: "nowrap" },
  genCard: { background: colors.bgSurface, border: `1px solid ${colors.border}`, borderRadius: 12, padding: "20px 24px" },
  genFooter: { display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 20, paddingTop: 16, borderTop: `1px solid ${colors.border}`, flexWrap: "wrap", gap: 10 },
  genCount: { color: colors.textMuted, fontSize: 12 },
  selectAllBtn: { background: "transparent", border: `1px solid ${colors.border}`, color: colors.textMuted, padding: "5px 12px", borderRadius: 6, cursor: "pointer", fontSize: 12 },
  generateBtn: { background: colors.accent, color: colors.bgPage, border: "none", padding: "7px 18px", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700, transition: "opacity 0.15s" },
  historyBox: { marginTop: 40 },
  historyTitle: { color: colors.textSecondary, fontSize: 13, marginBottom: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: { color: colors.textMuted, fontSize: 11, textAlign: "left", padding: "8px 12px", borderBottom: `1px solid ${colors.border}`, textTransform: "uppercase", letterSpacing: "0.05em" },
  tr: { borderBottom: `1px solid ${colors.border}` },
  td: { color: colors.textSecondary, fontSize: 14, padding: "10px 12px" },
  badge: { padding: "2px 8px", borderRadius: 4, fontSize: 12, fontWeight: 600 },
  viewBtn: { background: colors.accentBg, color: colors.accent, border: `1px solid ${colors.accent}55`, padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 12, fontWeight: 600 },
};

const modal: Record<string, React.CSSProperties> = {
  overlay: { position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: "1rem" },
  box: { background: colors.bgSurface, border: `1px solid ${colors.border}`, borderRadius: 12, width: "100%", maxWidth: 960, maxHeight: "88vh", display: "flex", flexDirection: "column", overflow: "hidden" },
  header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "20px 24px 0" },
  title: { color: colors.textPrimary, fontWeight: 700, fontSize: 16 },
  subtitle: { color: colors.textMuted, fontSize: 13, marginTop: 4 },
  closeBtn: { background: "transparent", border: "none", color: colors.textMuted, fontSize: 16, cursor: "pointer", padding: 4 },
  chips: { display: "flex", flexWrap: "wrap", gap: 8, padding: "14px 24px 0" },
  chip: { padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.04em" },
  tableWrap: { overflowY: "auto", overflowX: "auto", flex: 1, margin: "14px 0 0", borderTop: `1px solid ${colors.border}`, borderBottom: `1px solid ${colors.border}` },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { color: colors.textMuted, padding: "8px 12px", textAlign: "left", borderBottom: `1px solid ${colors.border}`, whiteSpace: "nowrap", background: colors.bgElevated, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.04em", position: "sticky", top: 0 },
  td: { color: colors.textSecondary, padding: "6px 12px", borderBottom: `1px solid ${colors.border}88` },
  typeBadge: { padding: "1px 7px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase", whiteSpace: "nowrap" },
  allowed: { padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, background: colors.successBg, color: colors.success },
  blocked: { padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, background: colors.dangerBg, color: colors.danger },
  methodPost: { padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, background: colors.warningBg, color: colors.warning },
  methodGet: { padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, background: colors.bgElevated, color: colors.textMuted },
  statusOk: { padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, background: colors.successBg, color: colors.success },
  statusBad: { padding: "1px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, background: colors.dangerBg, color: colors.danger },
  footer: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 24px", gap: 12, flexWrap: "wrap" },
  footerNote: { color: colors.textMuted, fontSize: 12, flex: 1 },
  cancelBtn: { background: "transparent", border: `1px solid ${colors.border}`, color: colors.textMuted, padding: "7px 18px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  importBtn: { background: colors.accent, color: colors.bgPage, border: "none", padding: "7px 18px", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700 },
};
