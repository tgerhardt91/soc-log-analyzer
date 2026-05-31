import { useState } from "react";
import { colors } from "../theme";

const BEHAVIORAL_TYPES = new Set(["beaconing", "slow_exfil", "ua_anomaly", "auth_abuse", "behavioral_detected"]);

type LogEntry = {
  id: string;
  timestamp: string | null;
  username: string | null;
  src_ip: string | null;
  dst_hostname: string | null;
  action: string | null;
  bytes_sent: number;
  threat_name: string | null;
};

type Anomaly = {
  id: string;
  anomaly_type: string;
  explanation: string;
  confidence: number;
  log_entries: LogEntry[];
};

export default function AnomalyPanel({ anomalies }: { anomalies: Anomaly[] }) {
  const [open, setOpen] = useState<string | null>(null);

  if (!anomalies.length) return (
    <div style={styles.empty}>No anomalies detected.</div>
  );

  const ruleAnomalies = anomalies.filter(a => !BEHAVIORAL_TYPES.has(a.anomaly_type));
  const aiAnomalies   = anomalies.filter(a =>  BEHAVIORAL_TYPES.has(a.anomaly_type));

  const renderAnomaly = (a: Anomaly) => (
    <div key={a.id} style={{
      ...styles.item,
      borderLeft: `3px solid ${typeBorderColor(a.anomaly_type)}`,
      boxShadow: open === a.id ? `0 0 16px ${typeBorderColor(a.anomaly_type)}22` : "none",
    }}>
      <div style={styles.header} onClick={() => setOpen(open === a.id ? null : a.id)}>
        <div style={styles.left}>
          <span style={{ ...styles.typeBadge, ...typeColor(a.anomaly_type) }}>
            {a.anomaly_type.replace(/_/g, " ")}
          </span>
          <span style={styles.explanation}>{a.explanation}</span>
        </div>
        <div style={styles.right}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 8 }}>
            <ConfidenceBadge score={a.confidence} />
            {(a.log_entries ?? []).length > 1 && (
              <span style={styles.eventCount}>{(a.log_entries ?? []).length} events</span>
            )}
          </div>
          <span style={styles.chevron}>{open === a.id ? "▼" : "►"}</span>
        </div>
      </div>
      {open === a.id && (
        <div style={styles.detail}>
          {(a.log_entries ?? []).length === 1 ? (
            <>
              <DetailRow label="Timestamp" value={a.log_entries[0].timestamp ? new Date(a.log_entries[0].timestamp).toLocaleString() : "—"} />
              <DetailRow label="User" value={a.log_entries[0].username ?? "—"} />
              <DetailRow label="Source IP" value={a.log_entries[0].src_ip ?? "—"} />
              <DetailRow label="Destination" value={a.log_entries[0].dst_hostname ?? "—"} />
              <DetailRow label="Action" value={a.log_entries[0].action ?? "—"} />
              <DetailRow label="Bytes Sent" value={a.log_entries[0].bytes_sent?.toLocaleString() ?? "—"} />
              {a.log_entries[0].threat_name && <DetailRow label="Threat" value={a.log_entries[0].threat_name} />}
            </>
          ) : (
            <div style={{ gridColumn: "1 / -1" }}>
              <div style={styles.linkedHeader}>{(a.log_entries ?? []).length} linked events</div>
              <div style={styles.linkedScroll}>
                <div style={styles.linkedTableHeader}>
                  <span>Timestamp</span><span>Source IP</span><span>Destination</span><span>Action</span>
                </div>
                {(a.log_entries ?? []).map((e) => (
                  <div key={e.id} style={styles.linkedRow}>
                    <span>{e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</span>
                    <span>{e.src_ip ?? "—"}</span>
                    <span style={styles.linkedDest}>{e.dst_hostname ?? "—"}</span>
                    <span>{e.action ?? "—"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );

  return (
    <div style={styles.container}>
      <h3 style={styles.title}>Anomalies Detected ({anomalies.length})</h3>
      <div style={styles.scroll}>
        {ruleAnomalies.length > 0 && (
          <>
            <div style={styles.sectionLabel}>Rule-Based Detection</div>
            {ruleAnomalies.map(renderAnomaly)}
          </>
        )}
        {aiAnomalies.length > 0 && (
          <>
            <div style={{ ...styles.sectionLabel, color: "#A78BFA", marginTop: ruleAnomalies.length > 0 ? 12 : 0 }}>
              Behavioral Detection
            </div>
            {aiAnomalies.map(renderAnomaly)}
          </>
        )}
      </div>
    </div>
  );
}

function ConfidenceBadge({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.8 ? colors.danger : score >= 0.6 ? colors.warning : colors.textMuted;
  return (
    <span style={{ ...styles.confidence, color, borderColor: `${color}66` }}>
      {pct}% confidence
    </span>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={styles.detailRow}>
      <span style={styles.detailLabel}>{label}</span>
      <span style={styles.detailValue}>{value}</span>
    </div>
  );
}

function typeBorderColor(t: string): string {
  if (t === "blocked_threat") return colors.danger;
  if (t === "data_exfil") return "#FB923C";
  if (t === "ip_spike") return colors.warning;
  if (t === "off_hours") return colors.accent;
  if (t === "auth_abuse") return colors.danger;
  if (t === "beaconing" || t === "slow_exfil" || t === "ua_anomaly" || t === "behavioral_detected") return "#7C3AED";
  return colors.textMuted;
}

function typeColor(t: string): React.CSSProperties {
  if (t === "blocked_threat") return { background: colors.dangerBg, color: colors.danger, border: `1px solid ${colors.dangerMid}` };
  if (t === "data_exfil") return { background: "#2C1008", color: "#FB923C", border: "1px solid #7C2D12" };
  if (t === "ip_spike") return { background: colors.warningBg, color: colors.warning, border: "1px solid #713F12" };
  if (t === "off_hours") return { background: colors.accentBg, color: colors.accent, border: `1px solid ${colors.accent}44` };
  if (t === "auth_abuse") return { background: colors.dangerBg, color: colors.danger, border: `1px solid ${colors.dangerMid}` };
  if (t === "beaconing" || t === "slow_exfil" || t === "ua_anomaly" || t === "behavioral_detected")
    return { background: "#1B0E3A", color: "#A78BFA", border: "1px solid #4C1D95" };
  return { background: colors.bgElevated, color: colors.textSecondary, border: `1px solid ${colors.border}` };
}

const styles: Record<string, React.CSSProperties> = {
  container: { marginBottom: 20 },
  scroll: { maxHeight: 425, overflowY: "auto", border: `1px solid ${colors.border}`, borderRadius: 8, padding: 8 },
  title: { color: colors.textMuted, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 12 },
  empty: { color: colors.textMuted, fontSize: 14, padding: "1rem 0" },
  item: {
    background: colors.bgSurface,
    borderRadius: 8,
    marginBottom: 8,
    overflow: "hidden",
    border: `1px solid ${colors.border}`,
    transition: "box-shadow 0.2s",
  },
  header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "12px 16px", cursor: "pointer", gap: 12 },
  left: { display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 6, flex: 1, minWidth: 0 },
  right: { display: "flex", alignItems: "flex-start", gap: 12, flexShrink: 0, paddingTop: 1 },
  sectionLabel: { color: colors.accent, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", padding: "4px 4px 8px" },
  typeBadge: { padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, textTransform: "uppercase", whiteSpace: "nowrap", flexShrink: 0 },
  explanation: { color: colors.textSecondary, fontSize: 14, lineHeight: 1.5 },
  eventCount: { fontSize: 11, fontWeight: 600, color: colors.textMuted, background: colors.bgElevated, border: `1px solid ${colors.border}`, borderRadius: 4, padding: "2px 7px", whiteSpace: "nowrap" as const },
  confidence: { fontSize: 12, fontWeight: 600, border: "1px solid", borderRadius: 4, padding: "2px 8px" },
  chevron: { color: colors.textMuted, fontSize: 10 },
  detail: {
    borderTop: `1px solid ${colors.border}`,
    padding: "12px 16px",
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 12,
    background: colors.bgPage,
  },
  detailRow: { display: "flex", flexDirection: "column" },
  detailLabel: { color: colors.textMuted, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.04em" },
  detailValue: { color: colors.textPrimary, fontSize: 13, marginTop: 3 },
  linkedHeader: { color: colors.textMuted, fontSize: 11, fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.04em", marginBottom: 8 },
  linkedScroll: { maxHeight: 180, overflowY: "auto" as const, border: `1px solid ${colors.border}`, borderRadius: 6 },
  linkedTableHeader: { display: "grid", gridTemplateColumns: "2fr 1fr 2fr 1fr", gap: 8, padding: "6px 10px", background: colors.bgElevated, color: colors.textMuted, fontSize: 11, fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.04em", position: "sticky" as const, top: 0 },
  linkedRow: { display: "grid", gridTemplateColumns: "2fr 1fr 2fr 1fr", gap: 8, padding: "6px 10px", borderTop: `1px solid ${colors.border}`, fontSize: 12, color: colors.textSecondary },
  linkedDest: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const },
};
