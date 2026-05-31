import React from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from "recharts";
import { colors } from "../theme";

type Bucket = { hour: string; total: number; blocked: number };

type Props = {
  data: Bucket[];
  selectedHour: string | null;
  onBarClick: (hour: string | null) => void;
};

function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number }>; label?: string }) {
  if (!active || !payload?.length) return null;
  const allowed = payload[0]?.value ?? 0;
  const blocked = payload[1]?.value ?? 0;
  const total = allowed + blocked;
  const pct = total > 0 ? Math.round((blocked / total) * 100) : 0;
  return (
    <div style={{ background: colors.bgElevated, border: `1px solid ${colors.border}`, borderRadius: 8, padding: "8px 12px", fontSize: 13 }}>
      <div style={{ color: colors.textSecondary, marginBottom: 6, fontWeight: 600 }}>{label}</div>
      <div style={{ color: colors.textPrimary, marginBottom: 2 }}>Total: {total}</div>
      <div style={{ color: colors.danger }}>Blocked: {blocked} ({pct}%)</div>
    </div>
  );
}

export default function Timeline({ data, selectedHour, onBarClick }: Props) {
  if (!data.length) return null;

  const formatted = data.map((d) => ({
    hour: d.hour,
    allowed: d.total - d.blocked,
    blocked: d.blocked,
    label: new Date(d.hour).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }));

  function handleClick(payload: { activePayload?: Array<{ payload: { hour: string } }> }) {
    const clickedHour = payload?.activePayload?.[0]?.payload?.hour;
    if (!clickedHour) return;
    onBarClick(selectedHour === clickedHour ? null : clickedHour);
  }

  return (
    <div style={styles.container}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h3 style={styles.title}>Request Volume by Hour</h3>
        <span style={styles.hint}>
          {selectedHour ? "Click selected bar to deselect" : "Click a bar to filter events"}
        </span>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart
          data={formatted}
          margin={{ top: 4, right: 16, bottom: 4, left: 0 }}
          onClick={handleClick}
          style={{ cursor: "pointer" }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke={colors.border} />
          <XAxis dataKey="label" tick={{ fill: colors.textMuted, fontSize: 11 }} />
          <YAxis tick={{ fill: colors.textMuted, fontSize: 11 }} />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: `${colors.accent}11` }} />
          <Bar dataKey="allowed" stackId="a" fill={colors.accent}>
            {formatted.map((entry) => (
              <Cell
                key={entry.hour}
                fill={colors.accent}
                fillOpacity={selectedHour && selectedHour !== entry.hour ? 0.25 : 1}
              />
            ))}
          </Bar>
          <Bar dataKey="blocked" stackId="a" fill={colors.danger} radius={[3, 3, 0, 0]}>
            {formatted.map((entry) => (
              <Cell
                key={entry.hour}
                fill={colors.danger}
                fillOpacity={selectedHour && selectedHour !== entry.hour ? 0.25 : 1}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    background: colors.bgSurface,
    border: `1px solid ${colors.border}`,
    borderRadius: 10,
    padding: "1.25rem 1.5rem",
    marginBottom: 20,
  },
  title: {
    color: colors.textMuted,
    fontSize: 11,
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.06em",
    margin: 0,
  },
  hint: {
    color: colors.textMuted,
    fontSize: 11,
    opacity: 0.7,
  },
};
