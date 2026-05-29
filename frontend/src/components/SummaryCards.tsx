import { colors } from "../theme";

type Props = {
  totalEvents: number;
  blockedCount: number;
  summary: string | null;
  anomalyCount: number;
  timeRange: { min: string | null; max: string | null };
};

export default function SummaryCards({ totalEvents, blockedCount, summary, anomalyCount, timeRange }: Props) {
  const blockedPct = totalEvents > 0 ? ((blockedCount / totalEvents) * 100).toFixed(1) : "0";
  const fmt = (iso: string | null) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div>
      {summary && (
        <div style={styles.summaryBox}>
          <div style={styles.summaryHeader}>
            <span style={styles.aiChip}>AI Summary</span>
          </div>
          <p style={styles.summaryText}>{summary}</p>
        </div>
      )}
      <div style={styles.grid}>
        <Card label="Total Events" value={totalEvents.toLocaleString()} />
        <Card label="Blocked" value={`${blockedCount.toLocaleString()}`} sub={`${blockedPct}% of traffic`} accent={colors.danger} />
        <Card label="Anomalies Detected" value={anomalyCount.toString()} accent={anomalyCount > 0 ? colors.warning : undefined} />
        <Card label="Time Range" value={fmt(timeRange.min)} sub={fmt(timeRange.max)} compact />
      </div>
    </div>
  );
}

function Card({ label, value, sub, accent, compact }: { label: string; value: string; sub?: string; accent?: string; compact?: boolean }) {
  return (
    <div style={styles.card}>
      <div style={styles.cardLabel}>{label}</div>
      {compact ? (
        <>
          <div style={styles.cardCompact}>{value}</div>
          {sub && (
            <>
              <div style={styles.cardCompactDivider}>→</div>
              <div style={styles.cardCompact}>{sub}</div>
            </>
          )}
        </>
      ) : (
        <>
          <div style={{ ...styles.cardValue, color: accent ?? colors.textPrimary }}>{value}</div>
          {sub && <div style={styles.cardSub}>{sub}</div>}
        </>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  summaryBox: {
    background: colors.bgSurface,
    borderRadius: 10,
    padding: "1.25rem 1.5rem",
    marginBottom: 20,
    border: `1px solid ${colors.border}`,
    borderLeft: `3px solid ${colors.accent}`,
    boxShadow: `inset 0 0 40px ${colors.accentBg}`,
  },
  summaryHeader: { marginBottom: 10 },
  aiChip: {
    background: colors.accentBg,
    color: colors.accent,
    border: `1px solid ${colors.accent}44`,
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    padding: "2px 8px",
    textTransform: "uppercase" as const,
    letterSpacing: "0.06em",
  },
  summaryText: { color: colors.textSecondary, fontSize: 14, lineHeight: 1.7, margin: 0 },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 20 },
  card: {
    background: colors.bgSurface,
    border: `1px solid ${colors.border}`,
    borderRadius: 10,
    padding: "1.25rem 1.5rem",
  },
  cardLabel: { color: colors.textMuted, fontSize: 11, textTransform: "uppercase" as const, letterSpacing: "0.06em", marginBottom: 8 },
  cardValue: { fontSize: 26, fontWeight: 700 },
  cardSub: { color: colors.textMuted, fontSize: 12, marginTop: 4 },
  cardCompact: { color: colors.textPrimary, fontSize: 13, fontWeight: 500, lineHeight: 1.5 },
  cardCompactDivider: { color: colors.textMuted, fontSize: 11, margin: "2px 0" },
};
