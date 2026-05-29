import { useState } from "react";

type Anomaly = {
  id: string;
  anomaly_type: string;
  explanation: string;
  confidence: number;
  log_entry: {
    timestamp: string | null;
    username: string | null;
    src_ip: string | null;
    dst_hostname: string | null;
    action: string | null;
    bytes_sent: number;
    threat_name: string | null;
  } | null;
};

export default function AnomalyPanel({ anomalies }: { anomalies: Anomaly[] }) {
  const [open, setOpen] = useState<string | null>(null);

  if (!anomalies.length) return (
    <div style={styles.empty}>No anomalies detected.</div>
  );

  return (
    <div style={styles.container}>
      <h3 style={styles.title}>Anomalies ({anomalies.length})</h3>
      {anomalies.map((a) => (
        <div key={a.id} style={styles.item}>
          <div style={styles.header} onClick={() => setOpen(open === a.id ? null : a.id)}>
            <div style={styles.left}>
              <span style={{ ...styles.typeBadge, ...typeColor(a.anomaly_type) }}>
                {a.anomaly_type.replace(/_/g, " ")}
              </span>
              <span style={styles.explanation}>{a.explanation}</span>
            </div>
            <div style={styles.right}>
              <ConfidenceBadge score={a.confidence} />
              <span style={styles.chevron}>{open === a.id ? "▲" : "▼"}</span>
            </div>
          </div>
          {open === a.id && a.log_entry && (
            <div style={styles.detail}>
              <DetailRow label="Timestamp" value={a.log_entry.timestamp ? new Date(a.log_entry.timestamp).toLocaleString() : "—"} />
              <DetailRow label="User" value={a.log_entry.username ?? "—"} />
              <DetailRow label="Source IP" value={a.log_entry.src_ip ?? "—"} />
              <DetailRow label="Destination" value={a.log_entry.dst_hostname ?? "—"} />
              <DetailRow label="Action" value={a.log_entry.action ?? "—"} />
              <DetailRow label="Bytes Sent" value={a.log_entry.bytes_sent?.toLocaleString() ?? "—"} />
              {a.log_entry.threat_name && <DetailRow label="Threat" value={a.log_entry.threat_name} />}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ConfidenceBadge({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.8 ? "#ef4444" : score >= 0.6 ? "#f59e0b" : "#64748b";
  return (
    <span style={{ ...styles.confidence, color, borderColor: color }}>
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

function typeColor(t: string): React.CSSProperties {
  if (t === "blocked_threat") return { background: "#7f1d1d", color: "#fca5a5" };
  if (t === "data_exfil") return { background: "#7c2d12", color: "#fdba74" };
  if (t === "ip_spike") return { background: "#713f12", color: "#fde047" };
  if (t === "off_hours") return { background: "#1e3a5f", color: "#93c5fd" };
  return { background: "#1e293b", color: "#94a3b8" };
}

const styles: Record<string, React.CSSProperties> = {
  container: { marginBottom: 24 },
  title: { color: "#94a3b8", fontSize: 13, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 },
  empty: { color: "#64748b", fontSize: 14, padding: "1rem 0" },
  item: { background: "#1e293b", borderRadius: 8, marginBottom: 8, overflow: "hidden", border: "1px solid #334155" },
  header: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", cursor: "pointer", gap: 12 },
  left: { display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0 },
  right: { display: "flex", alignItems: "center", gap: 12, flexShrink: 0 },
  typeBadge: { padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, textTransform: "uppercase", whiteSpace: "nowrap" },
  explanation: { color: "#cbd5e1", fontSize: 14, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  confidence: { fontSize: 12, fontWeight: 600, border: "1px solid", borderRadius: 4, padding: "2px 8px" },
  chevron: { color: "#64748b", fontSize: 10 },
  detail: { borderTop: "1px solid #334155", padding: "12px 16px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 },
  detailRow: { display: "flex", flexDirection: "column" },
  detailLabel: { color: "#64748b", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.04em" },
  detailValue: { color: "#f1f5f9", fontSize: 13, marginTop: 2 },
};
