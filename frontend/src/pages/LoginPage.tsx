import { useState, FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import { colors } from "../theme";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { data } = await api.post("/api/auth/login", { username, password });
      localStorage.setItem("token", data.token);
      navigate("/");
    } catch {
      setError("Invalid username or password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={styles.logoRow}>
          <div style={styles.logoMark}>⬡</div>
          <span style={styles.logoText}>SOC Log Analyzer</span>
        </div>
        <p style={styles.subtitle}>Sign in to your workspace</p>
        <form onSubmit={handleSubmit}>
          <div style={styles.field}>
            <label style={styles.label}>Username</label>
            <input
              style={styles.input}
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </div>
          <div style={styles.field}>
            <label style={styles.label}>Password</label>
            <input
              style={styles.input}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>
          {error && <p style={styles.error}>{error}</p>}
          <button style={styles.btn} type="submit" disabled={loading}>
            {loading ? "Signing in…" : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    background: colors.bgPage,
    fontFamily: "system-ui, sans-serif",
  },
  card: {
    background: colors.bgSurface,
    borderRadius: 12,
    padding: "2.5rem 2rem",
    width: 380,
    boxShadow: `0 0 0 1px ${colors.border}, 0 8px 48px rgba(0,0,0,0.6)`,
  },
  logoRow: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    marginBottom: 24,
  },
  logoMark: {
    width: 28,
    height: 28,
    borderRadius: 6,
    background: `linear-gradient(135deg, ${colors.accent}, ${colors.accentDim})`,
    boxShadow: `0 0 12px ${colors.accent}66`,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 14,
    color: colors.bgPage,
    fontWeight: 900,
  },
  logoText: {
    color: colors.textPrimary,
    fontWeight: 700,
    fontSize: 16,
  },
  title: { margin: 0, color: colors.textPrimary, fontSize: 22, fontWeight: 700 },
  subtitle: { color: colors.textMuted, marginTop: 6, marginBottom: 28, fontSize: 14 },
  field: { marginBottom: 16 },
  label: { display: "block", color: colors.textSecondary, fontSize: 13, marginBottom: 6 },
  input: {
    width: "100%",
    padding: "10px 12px",
    borderRadius: 8,
    border: `1px solid ${colors.border}`,
    background: colors.bgInput,
    color: colors.textPrimary,
    fontSize: 14,
    boxSizing: "border-box",
    outline: "none",
  },
  error: { color: colors.danger, fontSize: 13, marginTop: 8 },
  btn: {
    width: "100%",
    padding: "11px 0",
    marginTop: 8,
    borderRadius: 8,
    border: "none",
    background: `linear-gradient(135deg, ${colors.accent}, ${colors.accentDim})`,
    color: colors.bgPage,
    fontSize: 15,
    fontWeight: 700,
    cursor: "pointer",
    letterSpacing: "0.02em",
  },
};
