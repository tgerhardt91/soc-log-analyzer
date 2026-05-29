import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from "recharts";
import { colors } from "../theme";

type Bucket = { hour: string; total: number; blocked: number };

export default function Timeline({ data }: { data: Bucket[] }) {
  if (!data.length) return null;

  const formatted = data.map((d) => ({
    ...d,
    label: new Date(d.hour).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }));

  return (
    <div style={styles.container}>
      <h3 style={styles.title}>Request Volume by Hour</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={formatted} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={colors.border} />
          <XAxis dataKey="label" tick={{ fill: colors.textMuted, fontSize: 11 }} />
          <YAxis tick={{ fill: colors.textMuted, fontSize: 11 }} />
          <Tooltip
            contentStyle={{ background: colors.bgElevated, border: `1px solid ${colors.border}`, borderRadius: 8 }}
            labelStyle={{ color: colors.textSecondary }}
            itemStyle={{ color: colors.textPrimary }}
          />
          <Legend wrapperStyle={{ color: colors.textMuted, fontSize: 12 }} />
          <Bar dataKey="total" name="Total" fill={colors.accent} radius={[3, 3, 0, 0]} />
          <Bar dataKey="blocked" name="Blocked" fill={colors.danger} radius={[3, 3, 0, 0]} />
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
    marginBottom: 16,
  },
};
