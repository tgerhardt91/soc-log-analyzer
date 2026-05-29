type Props = {
  totalEvents: number;
  blockedCount: number;
  summary: string | null;
  anomalyCount: number;
  timeRange: { min: string | null; max: string | null };
};

export default function SummaryCards({ totalEvents, blockedCount, summary, anomalyCount, timeRange }: Props) {
  const blockedPct = totalEvents > 0 ? ((blockedCount / totalEvents) * 100).toFixed(1) : "0";

  const fmt = (iso: string | null) =>
    iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div>
      {summary && (
        <div style={styles.summaryBox}>
          <h3 style={styles.summaryTitle}>AI Summary</h3>
          <p style={styles.summaryText}>{summary}</p>
        </div>
      )}
      <div style={styles.grid}>
        <Card label="Total Events" value={totalEvents.toLocaleString()} />
        <Card label="Blocked" value={`${blockedCount.toLocaleString()} (${blockedPct}%)`} accent="#ef4444" />
        <Card label="Anomalies Detected" value={anomalyCount.toString()} accent={anomalyCount > 0 ? "#f59e0b" : undefined} />
        <Card label="Time Range" value={`${fmt(timeRange.min)}`} sub={`to ${fmt(timeRange.max)}`} />
      </div>
    </div>
  );
}

function Card({ label, value, sub, accent }: { label: string; value: string; sub?: string; accent?: string }) {
  return (
    <div style={styles.card}>
      <div style={styles.cardLabel}>{label}</div>
      <div style={{ ...styles.cardValue, color: accent ?? "#f1f5f9" }}>{value}</div>
      {sub && <div style={styles.cardSub}>{sub}</div>}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  summaryBox: { background: "#1e293b", borderRadius: 10, padding: "1.25rem 1.5rem", marginBottom: 20, borderLeft: "4px solid #3b82f6" },
  summaryTitle: { color: "#93c5fd", fontSize: 13, fontWeight: 600, marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em" },
  summaryText: { color: "#cbd5e1", fontSize: 15, lineHeight: 1.6, margin: 0 },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 16, marginBottom: 24 },
  card: { background: "#1e293b", borderRadius: 10, padding: "1.25rem 1.5rem" },
  cardLabel: { color: "#64748b", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 },
  cardValue: { fontSize: 24, fontWeight: 700 },
  cardSub: { color: "#64748b", fontSize: 12, marginTop: 4 },
};
